//! Tests for hmac_auth plugin

use base64::Engine;
use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::Consumer;
use ferrum_edge::plugins::utils::auth_flow::AuthMechanism;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, PluginResult, RequestContext, hmac_auth::HmacAuth, priority,
};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::sync::Arc;

use super::plugin_utils::{
    assert_continue, assert_reject, assert_reject_body, context_with_materialized_raw_header,
    context_with_materialized_raw_header_bytes, create_test_proxy,
};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const TEST_SECRET: &str = "my-hmac-secret-key-at-least-32-bytes";
const TEST_USERNAME: &str = "hmacuser";
const TEST_AUTHORITY: &str = "api.example.com";

/// The legacy `ferrum-hmac-v1` profile, explicitly acknowledged as unsafe.
///
/// Most cases in this file predate `ferrum-hmac-v2` and exercise the v1 signing
/// base, canonical-request binding, digest handling, and parser hardening. They
/// keep testing exactly that surface; the v2 single-use contract has its own
/// section at the end of the file.
fn default_config() -> Value {
    json!({
        "signing_profile": "ferrum-hmac-v1",
        "allow_unsafe_replayable_v1": true
    })
}

/// The default `ferrum-hmac-v2` profile with a process-scoped replay lane.
fn v2_config() -> Value {
    json!({"replay_scope": "process"})
}

/// Create a consumer with hmac_auth credentials.
fn create_hmac_consumer() -> Consumer {
    create_hmac_consumer_named("hmac-consumer", TEST_USERNAME, TEST_SECRET)
}

fn create_hmac_consumer_named(id: &str, username: &str, secret: &str) -> Consumer {
    let mut credentials = HashMap::new();
    let mut hmac_creds = Map::new();
    hmac_creds.insert("secret".to_string(), Value::String(secret.to_string()));
    credentials.insert(
        "hmac_auth".to_string(),
        Value::Array(vec![Value::Object(hmac_creds)]),
    );

    Consumer {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
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
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(keyauth_creds)]),
    );

    Consumer {
        id: "no-hmac-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "nokeyuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn make_ctx(method: &str, path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    );
    let empty_body = bytes::Bytes::new();
    ctx.headers
        .insert("digest".to_string(), sha256_digest_header(&empty_body));
    ctx.request_body_sha256 = Some(Sha256::digest(&empty_body).into());
    ctx.request_body_sha512 = Some(Sha512::digest(&empty_body).into());
    ctx.request_authority = Some(TEST_AUTHORITY.to_string());
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx
}

/// Like `make_ctx` but also sets the raw query string (as the proxy would on
/// request init), so the query string is bound into the HMAC signing string.
fn make_ctx_with_query(method: &str, path: &str, query: &str) -> RequestContext {
    let mut ctx = make_ctx(method, path);
    ctx.set_raw_query_string(query.to_string());
    ctx
}

fn set_ctx_namespace(ctx: &mut RequestContext, namespace: &str) {
    let mut proxy = create_test_proxy();
    proxy.namespace = namespace.to_string();
    ctx.matched_proxy = Some(Arc::new(proxy));
}

/// Generate a current RFC 2822 date string.
fn current_date() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// Version 1 binds credential identity and authority before the request fields.
/// `make_ctx` produces requests with no
/// query, so the helpers below sign an empty query by default; tests that set
/// a query string use `sign_sha256_with_query`.
fn build_signing_string(input: HmacSigningInput<'_>) -> String {
    format!(
        "ferrum-hmac-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        input.namespace,
        input.username,
        input.authority,
        input.method,
        input.path,
        input.query,
        input.date,
        input.digest_header
    )
}

/// Compute an HMAC-SHA256 signature over an empty-body, no-query request.
fn sign_sha256(secret: &str, method: &str, path: &str, date: &str) -> String {
    sign_sha256_with_digest(secret, method, path, date, &sha256_digest_header(&[]))
}

/// Compute an HMAC-SHA512 signature over an empty-body, no-query request.
fn sign_sha512(secret: &str, method: &str, path: &str, date: &str) -> String {
    let digest_header = sha256_digest_header(&[]);
    let signing_string = build_signing_string(HmacSigningInput {
        namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
        username: TEST_USERNAME,
        authority: TEST_AUTHORITY,
        method,
        path,
        query: "",
        date,
        digest_header: &digest_header,
    });
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Compute an HMAC-SHA256 signature over version 1 with the default test
/// identity, authority, and an empty query.
fn sign_sha256_with_digest(
    secret: &str,
    method: &str,
    path: &str,
    date: &str,
    digest_header: &str,
) -> String {
    sign_sha256_for_identity(
        secret,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: TEST_USERNAME,
            authority: TEST_AUTHORITY,
            method,
            path,
            query: "",
            date,
            digest_header,
        },
    )
}

struct HmacSigningInput<'a> {
    namespace: &'a str,
    username: &'a str,
    authority: &'a str,
    method: &'a str,
    path: &'a str,
    query: &'a str,
    date: &'a str,
    digest_header: &'a str,
}

fn sign_sha256_for_identity(secret: &str, input: HmacSigningInput<'_>) -> String {
    let signing_string = build_signing_string(input);
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Compute an HMAC-SHA256 signature binding a specific raw query string.
fn sign_sha256_with_query(
    secret: &str,
    method: &str,
    path: &str,
    query: &str,
    date: &str,
) -> String {
    let digest_header = sha256_digest_header(&[]);
    sign_sha256_for_identity(
        secret,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: TEST_USERNAME,
            authority: TEST_AUTHORITY,
            method,
            path,
            query,
            date,
            digest_header: &digest_header,
        },
    )
}

/// Build a `Digest:` (RFC 3230) header value of the form `sha-256=<base64>`
/// for the given body bytes.
fn sha256_digest_header(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    format!("sha-256={}", b64)
}

/// Build an RFC 9530 `Content-Digest` SHA-256 structured field.
fn sha256_content_digest_header(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

fn sha512_content_digest_header(body: &[u8]) -> String {
    format!(
        "sha-512=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(body))
    )
}

/// Build a `Digest:` header value of the form `sha-512=<base64>`.
fn sha512_digest_header(body: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(body);
    let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
    format!("sha-512={}", b64)
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

fn set_legacy_digest(ctx: &mut RequestContext, value: String) {
    ctx.headers.remove("content-digest");
    ctx.headers.insert("digest".to_string(), value);
}

fn set_content_digest(ctx: &mut RequestContext, value: String) {
    ctx.headers.remove("digest");
    ctx.headers.insert("content-digest".to_string(), value);
}

fn assert_reject_error(result: PluginResult, expected_status: u16, needle: &str) {
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, expected_status, "body={body}");
            assert!(
                body.contains(needle),
                "expected {needle:?} in rejection body {body}"
            );
        }
        other => panic!("Expected Reject, got {other:?}"),
    }
}

// ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_hmac_auth_plugin_creation() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    assert_eq!(plugin.name(), "hmac_auth");
    assert!(plugin.is_auth_plugin());
    assert_eq!(plugin.priority(), priority::HMAC_AUTH);
    assert_eq!(plugin.priority(), 1400);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[tokio::test]
async fn test_hmac_auth_custom_clock_skew() {
    let plugin = HmacAuth::new(&json!({
        "clock_skew_seconds": 120,
        "signing_profile": "ferrum-hmac-v1",
        "allow_unsafe_replayable_v1": true
    }))
    .unwrap();
    assert_eq!(plugin.name(), "hmac_auth");
}

#[test]
fn test_hmac_auth_rejects_invalid_config() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({"clock_skew_seconds": "300"}),
        json!({"clock_skew_seconds": -1}),
        json!({"require_digest": "true"}),
        json!({"require_digest": false}),
        // The default profile is single-use, and single-use requires a declared
        // replay scope: an empty config must not silently become one that
        // accepts one replay per replica.
        json!({}),
        json!({"replay_scope": "process", "clock_skew_seconds": 0}),
        json!({"replay_scope": "process", "clock_skew_seconds": 301}),
        json!({"replay_scope": "prosess"}),
        json!({"replay_scope": true}),
        json!({"replay_scope": "process", "replay_max_entries": 0}),
        // The legacy profile needs its own explicit acknowledgement, and the
        // acknowledgement is meaningless without it.
        json!({"signing_profile": "ferrum-hmac-v1"}),
        json!({"signing_profile": "ferrum-hmac-v3", "allow_unsafe_replayable_v1": true}),
        json!({"replay_scope": "process", "allow_unsafe_replayable_v1": true}),
        // The legacy profile has no replay state at all, so replay knobs and a
        // Redis backend must be refused rather than silently ignored.
        json!({
            "signing_profile": "ferrum-hmac-v1",
            "allow_unsafe_replayable_v1": true,
            "replay_scope": "process"
        }),
        json!({
            "signing_profile": "ferrum-hmac-v1",
            "allow_unsafe_replayable_v1": true,
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379"
        }),
        // Scope and backend must agree in both directions.
        json!({"replay_scope": "shared"}),
        json!({
            "replay_scope": "process",
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379"
        }),
        // Closed root key set: a misspelled security field fails admission.
        json!({"replay_scope": "process", "replay_scop": "shared"}),
    ];

    for config in invalid_configs {
        assert!(
            HmacAuth::new(&config).is_err(),
            "config should be rejected: {config}"
        );
    }
}

/// The closed-root-key diagnostic must name the plugin and the offending key.
///
/// A misspelled security field is exactly the case this refusal exists for, so
/// the operator has to be able to read which plugin refused and which key it
/// refused — an unseparated prefix (`hmac_authunknown configuration key(s)`)
/// buries the plugin name inside the sentence.
#[test]
fn test_hmac_auth_unknown_key_diagnostic_names_the_plugin_and_the_key() {
    let config = json!({"replay_scope": "process", "replay_scop": "shared"});
    // `HmacAuth` is deliberately not `Debug`, so unwrap the error by pattern
    // rather than through `expect_err`.
    let Err(error) = HmacAuth::new(&config) else {
        panic!("a misspelled root key must be refused");
    };
    assert!(
        error.starts_with("hmac_auth: unknown configuration key(s):"),
        "diagnostic must be plugin-qualified: {error}"
    );
    assert!(
        error.contains("'config.replay_scop'"),
        "diagnostic must name the offending key: {error}"
    );
    assert!(
        error.contains("replay_scope"),
        "diagnostic must suggest the intended key: {error}"
    );
}

#[tokio::test]
async fn test_hmac_auth_default_requires_digest() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    assert!(plugin.requires_request_body_before_authenticate());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());
    assert!(plugin.needs_request_body_digests());
}

#[tokio::test]
async fn test_hmac_auth_always_requires_body() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    assert!(plugin.requires_request_body_before_authenticate());
    assert!(plugin.requires_request_body_buffering());
    assert!(!plugin.needs_request_body_bytes());
    assert!(plugin.needs_request_body_digests());
    assert!(!plugin.needs_request_body_text());
    assert_eq!(plugin.request_body_buffer_limit(), Some(10 * 1024 * 1024));
}

#[tokio::test]
async fn test_hmac_auth_prebuffer_only_for_hmac_authorization() {
    let plugin = HmacAuth::new(&default_config()).unwrap();

    let mut missing = make_ctx("POST", "/test");
    assert!(!plugin.should_buffer_request_body(&missing));

    missing
        .headers
        .insert("authorization".to_string(), "Bearer token".to_string());
    assert!(!plugin.should_buffer_request_body(&missing));

    missing.headers.insert(
        "authorization".to_string(),
        r#"hmac username="u", signature="s""#.to_string(),
    );
    assert!(plugin.should_buffer_request_body(&missing));
}

// ── 1. Valid HMAC-SHA256 authentication (digest signing) ─────

#[tokio::test]
async fn test_valid_hmac_sha256() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
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

#[tokio::test]
async fn test_auth_params_accept_quoted_commas_escapes_and_mixed_case_names() {
    let username = "ops,\"blue\\team";
    let consumer = create_hmac_consumer_named("quoted-user", username, TEST_SECRET);
    let consumer_index = ConsumerIndex::new(&[consumer]);
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let method = "GET";
    let path = "/quoted";
    let date = current_date();
    let digest = sha256_digest_header(&[]);
    let signature = sign_sha256_for_identity(
        TEST_SECRET,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username,
            authority: TEST_AUTHORITY,
            method,
            path,
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            r#"hmac UserName="ops,\"blue\\team", ALGORITHM="hmac-sha256", Signature="{}""#,
            signature
        ),
    );
    ctx.headers.insert("date".to_string(), date);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, username);
}

#[tokio::test]
async fn test_auth_params_reject_unclosed_quotes_and_duplicates() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    for authorization in [
        r#"hmac username="hmacuser, algorithm="hmac-sha256", signature="abc""#,
        r#"hmac username="hmacuser", Username="other", signature="abc""#,
        r#"hmac username="hmacuser", signature="abc", Signature="def""#,
    ] {
        let mut ctx = make_ctx("GET", "/test");
        ctx.headers
            .insert("authorization".to_string(), authorization.to_string());
        ctx.headers.insert("date".to_string(), current_date());
        assert_reject(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            Some(401),
        );
    }
}

#[tokio::test]
async fn test_signature_binds_authority_and_username() {
    let shared = "shared-hmac-secret-at-least-32-characters";
    let consumers = [
        create_hmac_consumer_named("alice-id", "alice", shared),
        create_hmac_consumer_named("bob-id", "bob", shared),
    ];
    let consumer_index = ConsumerIndex::new(&consumers);
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let date = current_date();
    let digest = sha256_digest_header(&[]);
    let signature = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: "alice",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );

    let mut relabeled = make_ctx("GET", "/bound");
    relabeled.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("bob", Some("hmac-sha256"), &signature),
    );
    relabeled.headers.insert("date".to_string(), date.clone());
    assert_reject(
        plugin.authenticate(&mut relabeled, &consumer_index).await,
        Some(401),
    );

    let mut cross_host = make_ctx("GET", "/bound");
    cross_host.request_authority = Some("other.example.com".to_string());
    cross_host.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("alice", Some("hmac-sha256"), &signature),
    );
    cross_host.headers.insert("date".to_string(), date);
    assert_reject(
        plugin.authenticate(&mut cross_host, &consumer_index).await,
        Some(401),
    );
}

#[tokio::test]
async fn test_signature_and_identity_lookup_are_namespace_scoped() {
    let shared = "cross-namespace-reused-hmac-secret-at-least-32-characters";
    let mut tenant_a = create_hmac_consumer_named("tenant-a-id", "alice", shared);
    tenant_a.namespace = "tenant-a".to_string();
    let mut tenant_b = create_hmac_consumer_named("tenant-b-id", "bob", shared);
    tenant_b.namespace = "tenant-b".to_string();
    let consumer_index = ConsumerIndex::new(&[tenant_a, tenant_b]);
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let date = current_date();
    let digest = sha256_digest_header(&[]);

    let tenant_a_signature = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: "tenant-a",
            username: "alice",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut replayed_in_tenant_b = make_ctx("GET", "/bound");
    set_ctx_namespace(&mut replayed_in_tenant_b, "tenant-b");
    replayed_in_tenant_b.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("alice", Some("hmac-sha256"), &tenant_a_signature),
    );
    replayed_in_tenant_b
        .headers
        .insert("date".to_string(), date.clone());
    assert_reject(
        plugin
            .authenticate(&mut replayed_in_tenant_b, &consumer_index)
            .await,
        Some(401),
    );

    let tenant_b_wrong_identity = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: "tenant-b",
            username: "alice",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut wrong_identity = make_ctx("GET", "/bound");
    set_ctx_namespace(&mut wrong_identity, "tenant-b");
    wrong_identity.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("alice", Some("hmac-sha256"), &tenant_b_wrong_identity),
    );
    wrong_identity
        .headers
        .insert("date".to_string(), date.clone());
    assert_reject(
        plugin
            .authenticate(&mut wrong_identity, &consumer_index)
            .await,
        Some(401),
    );

    let tenant_b_signature = sign_sha256_for_identity(
        shared,
        HmacSigningInput {
            namespace: "tenant-b",
            username: "bob",
            authority: TEST_AUTHORITY,
            method: "GET",
            path: "/bound",
            query: "",
            date: &date,
            digest_header: &digest,
        },
    );
    let mut valid_tenant_b = make_ctx("GET", "/bound");
    set_ctx_namespace(&mut valid_tenant_b, "tenant-b");
    valid_tenant_b.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("bob", Some("hmac-sha256"), &tenant_b_signature),
    );
    valid_tenant_b.headers.insert("date".to_string(), date);
    assert_continue(
        plugin
            .authenticate(&mut valid_tenant_b, &consumer_index)
            .await,
    );
    assert_eq!(
        valid_tenant_b.identified_consumer.unwrap().id,
        "tenant-b-id"
    );
}

#[tokio::test]
async fn test_pre_auth_body_screening_requires_a_verified_signature() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, "POST", "/upload", &date);
    let mut valid = make_ctx("POST", "/upload");
    valid.request_body_bytes = None;
    valid.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    valid.headers.insert("date".to_string(), date.clone());
    assert!(plugin.should_buffer_request_body_before_authenticate(&valid, &consumer_index));

    // A wrong-secret signature is still well-formed base64 with exactly the
    // expected 32-byte decoded length. Knowing a real username must not be
    // enough to opt into the 10 MiB pre-auth collection budget.
    let wrong_signature = sign_sha256(
        "wrong-secret-that-is-still-long-enough-for-the-test",
        "POST",
        "/upload",
        &date,
    );
    let mut known_wrong = make_ctx("POST", "/upload");
    known_wrong.request_body_bytes = None;
    known_wrong.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &wrong_signature),
    );
    known_wrong.headers.insert("date".to_string(), date.clone());
    let known_wrong_buffers =
        plugin.should_buffer_request_body_before_authenticate(&known_wrong, &consumer_index);

    let mut unknown = make_ctx("POST", "/upload");
    unknown.request_body_bytes = None;
    unknown.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("unknown", Some("hmac-sha256"), &wrong_signature),
    );
    unknown.headers.insert("date".to_string(), date.clone());
    let unknown_buffers =
        plugin.should_buffer_request_body_before_authenticate(&unknown, &consumer_index);

    assert!(!known_wrong_buffers);
    assert_eq!(known_wrong_buffers, unknown_buffers);

    // Both non-buffered paths must also expose the same authentication result,
    // independent of whether the username exists.
    let known_wrong_reject = match plugin.authenticate(&mut known_wrong, &consumer_index).await {
        PluginResult::Reject {
            status_code, body, ..
        } => (status_code, body),
        other => panic!("expected known wrong signature to reject, got {other:?}"),
    };
    let unknown_reject = match plugin.authenticate(&mut unknown, &consumer_index).await {
        PluginResult::Reject {
            status_code, body, ..
        } => (status_code, body),
        other => panic!("expected unknown consumer to reject, got {other:?}"),
    };
    assert_eq!(known_wrong_reject, unknown_reject);

    let mut malformed = make_ctx("POST", "/upload");
    malformed.headers.insert(
        "authorization".to_string(),
        r#"hmac username="hmacuser", signature="not-base64""#.to_string(),
    );
    malformed.headers.insert("date".to_string(), date);
    assert!(!plugin.should_buffer_request_body_before_authenticate(&malformed, &consumer_index));
}

#[tokio::test]
async fn test_preverified_reuse_still_rejects_final_digest_mismatch() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let method = "POST";
    let path = "/upload";
    let date = current_date();
    let signed_body = br#"{"amount":1}"#;
    let digest = sha256_digest_header(signed_body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut tampered = make_ctx(method, path);
    tampered.request_body_sha256 = None;
    tampered.request_body_sha512 = None;
    tampered.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    tampered.headers.insert("date".to_string(), date.clone());
    tampered
        .headers
        .insert("digest".to_string(), digest.clone());

    assert!(
        plugin.should_buffer_request_body_before_authenticate(&tampered, &consumer_index),
        "a valid pre-body signature must enable body collection"
    );
    assert!(
        format!("{tampered:?}").contains("HmacPrebufferState { staged: 1 }"),
        "the request-scoped reuse path should be staged"
    );
    assert!(
        format!("{:?}", tampered.clone()).contains("HmacPrebufferState { staged: 0 }"),
        "request-context clones must not inherit staged HMAC credentials"
    );

    set_request_body(&mut tampered, br#"{"amount":999}"#);
    assert_reject(
        plugin.authenticate(&mut tampered, &consumer_index).await,
        Some(401),
    );
    assert!(tampered.identified_consumer.is_none());

    // Exercise the same staged path with matching bytes to prove the
    // preverified signature remains sufficient to reach post-body auth.
    let mut valid = make_ctx(method, path);
    valid.request_body_sha256 = None;
    valid.request_body_sha512 = None;
    valid.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    valid.headers.insert("date".to_string(), date);
    valid.headers.insert("digest".to_string(), digest);
    assert!(plugin.should_buffer_request_body_before_authenticate(&valid, &consumer_index));
    set_request_body(&mut valid, signed_body);
    assert_continue(plugin.authenticate(&mut valid, &consumer_index).await);
    assert_eq!(valid.identified_consumer.unwrap().username, TEST_USERNAME);
}

#[tokio::test]
async fn test_preverified_reuse_verifies_seeded_empty_body_digests() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    for method in ["GET", "HEAD", "OPTIONS"] {
        let path = "/empty";
        let date = current_date();
        let digest = sha256_content_digest_header(&[]);
        let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);
        let mut ctx = make_ctx(method, path);
        ctx.request_body_sha256 = None;
        ctx.request_body_sha512 = None;
        ctx.headers.remove("digest");
        ctx.headers.insert(
            "authorization".to_string(),
            hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
        );
        ctx.headers.insert("date".to_string(), date);
        set_content_digest(&mut ctx, digest);

        assert!(
            plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
            "{method} should stage a correctly signed empty-body request"
        );
        // Mirrors the shared proxy boundary after Incoming has definitively
        // reported END_STREAM without requiring body collection.
        set_request_body(&mut ctx, &[]);
        assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
        assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
    }

    for method in ["GET", "HEAD", "OPTIONS"] {
        let path = "/empty";
        let date = current_date();
        let incorrect_digest = sha256_content_digest_header(b"not empty");
        let signature =
            sign_sha256_with_digest(TEST_SECRET, method, path, &date, &incorrect_digest);
        let mut ctx = make_ctx(method, path);
        ctx.request_body_sha256 = None;
        ctx.request_body_sha512 = None;
        ctx.headers.remove("digest");
        ctx.headers.insert(
            "authorization".to_string(),
            hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
        );
        ctx.headers.insert("date".to_string(), date);
        set_content_digest(&mut ctx, incorrect_digest);

        assert!(
            plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
            "{method} has a valid signature even though its body digest is wrong"
        );
        set_request_body(&mut ctx, &[]);
        assert_reject(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            Some(401),
        );
        assert!(ctx.identified_consumer.is_none());
    }
}

#[tokio::test]
async fn test_preverified_reuse_discards_changed_authorization() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let method = "POST";
    let path = "/upload";
    let date = current_date();
    let body = br#"{"amount":1}"#;
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.request_body_sha256 = None;
    ctx.request_body_sha512 = None;
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date.clone());
    ctx.headers.insert("digest".to_string(), digest);
    assert!(plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));

    // No plug-in hook runs between screening and authentication in H1/H2/H3,
    // but bind the cache defensively so a future lifecycle change cannot reuse
    // a preverified result after the credential header changes.
    let wrong_signature = sign_sha256_with_digest(
        "wrong-secret-that-cannot-authenticate",
        method,
        path,
        &date,
        ctx.headers.get("digest").unwrap(),
    );
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &wrong_signature),
    );
    set_request_body(&mut ctx, body);
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
    assert!(ctx.identified_consumer.is_none());
}

// ── 2. Valid HMAC-SHA512 authentication (digest signing) ─────

#[tokio::test]
async fn test_valid_hmac_sha512() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut ctx = make_ctx("GET", "/test");
    // No authorization header set
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

// ── 4. Invalid auth format (not starting with "hmac ") ──────────────

#[tokio::test]
async fn test_invalid_auth_format_bearer() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    // Use a very tight clock skew of 1 second. The signing helper below builds a
    // `ferrum-hmac-v1` base, so this fixture is deliberately the acknowledged
    // legacy profile rather than the modern default.
    let plugin = HmacAuth::new(&json!({
        "clock_skew_seconds": 1,
        "signing_profile": "ferrum-hmac-v1",
        "allow_unsafe_replayable_v1": true
    }))
    .unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
async fn test_malformed_base64_signature_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), "not base64!"),
    );
    ctx.headers.insert("date".to_string(), current_date());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_signature_wrong_secret() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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

// ── Query-string binding (#30) ───────────────────────────────────────

#[tokio::test]
async fn test_valid_signature_with_query_string() {
    // A signature that binds the request's query string verifies when the
    // request carries exactly that query.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/transfer";
    let query = "account=alice&amount=100";
    let date = current_date();
    let signature = sign_sha256_with_query(TEST_SECRET, method, path, query, &date);

    let mut ctx = make_ctx_with_query(method, path, query);
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
async fn test_signature_query_param_tampering_rejected() {
    // #30: the signing string binds the query string, so replaying a captured
    // signature against the same path with an altered query parameter
    // (account=alice -> account=victim) must fail verification.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/transfer";
    let date = current_date();
    // Client legitimately signed `account=alice`...
    let signature = sign_sha256_with_query(TEST_SECRET, method, path, "account=alice", &date);

    // ...but the request arrives with the query tampered to `account=victim`.
    let mut ctx = make_ctx_with_query(method, path, "account=victim");
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
async fn test_signature_added_query_param_rejected() {
    // #30: a signature computed over a request with no query must not verify
    // when an attacker adds query parameters to the replayed request.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/transfer";
    let date = current_date();
    // Signed with no query string.
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    // Replayed with an added query parameter.
    let mut ctx = make_ctx_with_query(method, path, "admin=true");
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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
    let plugin = HmacAuth::new(&default_config()).unwrap();
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

// ---- Multi-credential rotation tests ----

fn create_hmac_consumer_with_secrets(secrets: &[&str]) -> Consumer {
    let mut credentials = HashMap::new();
    let arr: Vec<Value> = secrets.iter().map(|s| json!({"secret": s})).collect();
    credentials.insert("hmac_auth".to_string(), Value::Array(arr));

    Consumer {
        id: "hmac-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "hmacuser".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_hmac_multi_secret_old_secret_still_works() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer_with_secrets(&["old-secret", "new-secret"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let date = current_date();
    let sig = sign_sha256("old-secret", "GET", "/api", &date);
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"hmacuser\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            sig
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "hmacuser");
}

#[tokio::test]
async fn test_hmac_multi_secret_new_secret_works() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer_with_secrets(&["old-secret", "new-secret"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let date = current_date();
    let sig = sign_sha256("new-secret", "GET", "/api", &date);
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"hmacuser\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            sig
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "hmacuser");
}

#[tokio::test]
async fn test_hmac_multi_secret_wrong_secret_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer_with_secrets(&["secret-a", "secret-b"]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let date = current_date();
    let sig = sign_sha256("wrong-secret", "GET", "/api", &date);
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"hmacuser\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            sig
        ),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ────────────────────────────────────────────────────────────────────
// Digest verification tests.
// ────────────────────────────────────────────────────────────────────

/// Helper to populate body hashes the same way `store_request_body_metadata`
/// does for `hmac_auth` (`needs_request_body_digests`, no text/bytes copies).
fn set_request_body(ctx: &mut RequestContext, body: &[u8]) {
    ctx.request_body_sha256 = Some(Sha256::digest(body).into());
    ctx.request_body_sha512 = Some(Sha512::digest(body).into());
}

#[tokio::test]
async fn test_digest_required_valid_signature_with_correct_body() {
    // Default config signs and verifies the request body digest.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = br#"{"hello":"world"}"#;
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "hmacuser"
    );
}

#[tokio::test]
async fn test_digest_required_modified_body_rejected() {
    // Same Digest header + same HMAC signature, but the body was modified
    // after signing — must be rejected.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let original_body = br#"{"amount":1}"#;
    let digest = sha256_digest_header(original_body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    // Attacker swaps body but reuses the captured Digest+signature.
    let tampered_body = br#"{"amount":1000000}"#;
    set_request_body(&mut ctx, tampered_body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_digest_required_missing_digest_header_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = br#"{"hello":"world"}"#;
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    // Intentionally do not set the digest header.
    ctx.headers.remove("digest");
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_missing_digest_rejected() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let signature = sign_sha256(TEST_SECRET, method, path, &date);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.remove("digest");
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_digest_required_tampered_digest_header_rejected() {
    // Attacker recomputes a digest matching their tampered body, but lacks
    // the secret to re-sign — the HMAC mismatches because the digest header
    // is part of the signing string.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let original_body = br#"{"amount":1}"#;
    let original_digest = sha256_digest_header(original_body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &original_digest);

    // Attacker substitutes a tampered body AND recomputes the digest header
    // to match the tampered body. Without the HMAC secret they cannot
    // re-sign, so they reuse the old signature.
    let tampered_body = br#"{"amount":9999999}"#;
    let tampered_digest = sha256_digest_header(tampered_body);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), tampered_digest);
    set_request_body(&mut ctx, tampered_body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_digest_required_sha512_digest_accepted() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = b"some payload bytes";
    let digest = sha512_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_digest_required_content_digest_header_accepted() {
    // RFC 9530 Content-Digest structured-field form is accepted.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "POST";
    let path = "/api/data";
    let date = current_date();
    let body = br#"{"hello":"world"}"#;
    let legacy_digest = sha256_digest_header(body);
    let digest = format!("sha-256=:{}:", legacy_digest.trim_start_matches("sha-256="));
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    set_content_digest(&mut ctx, digest);
    set_request_body(&mut ctx, body);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_digest_required_empty_body_with_digest() {
    // GET requests with empty body still must include a valid digest header
    // with digest signing enabled.
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer = create_hmac_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let method = "GET";
    let path = "/api/data";
    let date = current_date();
    let body = b"";
    let digest = sha256_digest_header(body);
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header("hmacuser", Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    // Empty-body hash snapshots were populated by `make_ctx`.
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// `verify_body_digest` is a `pub(crate)` helper — its dedicated tests live
// inline in `src/plugins/hmac_auth.rs::tests` since `tests/` is a separate
// crate that can't see crate-private items. The end-to-end auth flow is
// covered above (correct-body vs. tampered-body vs. tampered-digest).

// ────────────────────────────────────────────────────────────────────
// Issue #3837 — `ferrum-hmac-v2` single-use signed requests
// ────────────────────────────────────────────────────────────────────

/// Build the v2 signing base: identical to v1 except for the version field and
/// the trailing bound nonce.
fn build_v2_signing_string(input: HmacSigningInput<'_>, nonce: &str) -> String {
    format!(
        "ferrum-hmac-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        input.namespace,
        input.username,
        input.authority,
        input.method,
        input.path,
        input.query,
        input.date,
        input.digest_header,
        nonce
    )
}

fn sign_v2(secret: &str, input: HmacSigningInput<'_>, nonce: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(build_v2_signing_string(input, nonce).as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

fn v2_auth_header(username: &str, nonce: &str, signature: &str) -> String {
    format!(
        r#"hmac username="{username}", algorithm="hmac-sha256", nonce="{nonce}", signature="{signature}""#
    )
}

/// 32 lowercase hex characters — 128 bits, the minimum admissible hex nonce.
fn test_nonce(seed: u64) -> String {
    format!("{seed:032x}")
}

struct V2Request {
    method: String,
    path: String,
    date: String,
    digest: String,
    nonce: String,
    signature: String,
}

impl V2Request {
    fn new(nonce: &str) -> Self {
        let method = "POST".to_string();
        let path = "/api/orders".to_string();
        let date = current_date();
        let digest = sha256_digest_header(b"");
        let signature = sign_v2(
            TEST_SECRET,
            HmacSigningInput {
                namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
                username: TEST_USERNAME,
                authority: TEST_AUTHORITY,
                method: &method,
                path: &path,
                query: "",
                date: &date,
                digest_header: &digest,
            },
            nonce,
        );
        Self {
            method,
            path,
            date,
            digest,
            nonce: nonce.to_string(),
            signature,
        }
    }

    fn context(&self) -> RequestContext {
        let mut ctx = make_ctx(&self.method, &self.path);
        ctx.headers.insert(
            "authorization".to_string(),
            v2_auth_header(TEST_USERNAME, &self.nonce, &self.signature),
        );
        ctx.headers.insert("date".to_string(), self.date.clone());
        ctx.headers
            .insert("digest".to_string(), self.digest.clone());
        ctx.identified_consumer = None;
        ctx
    }
}

fn v2_plugin_named(config_id: &str) -> HmacAuth {
    HmacAuth::new_with_http_client_and_config_id(
        &v2_config(),
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some(config_id),
    )
    .expect("v2 config with a declared process replay scope")
}

// ── the default posture is single-use ───────────────────────────────

#[test]
fn v2_is_the_default_profile_and_requires_a_declared_replay_scope() {
    let plugin = HmacAuth::new(&v2_config()).expect("declared process scope");
    assert_eq!(plugin.replay_mode(), Some("process"));

    let error = HmacAuth::new(&json!({}))
        .map(|_| ())
        .expect_err("the single-use default must not silently pick a replay scope");
    assert!(
        error.contains("replay_scope"),
        "diagnostic should name the missing declaration: {error}"
    );
}

// ── the acceptance contract ─────────────────────────────────────────

#[tokio::test]
async fn v2_first_request_succeeds_and_exact_replay_is_rejected() {
    let plugin = v2_plugin_named("v2-sequential");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let request = V2Request::new(&test_nonce(1));

    let mut first = request.context();
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);

    // Byte-for-byte identical resubmission — a verbatim transport retry is a
    // replay, not a second legitimate request.
    let mut replay = request.context();
    assert_reject(
        plugin.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

#[tokio::test]
async fn v2_fresh_nonce_with_recomputed_signature_succeeds() {
    let plugin = v2_plugin_named("v2-fresh-nonce");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let mut first = V2Request::new(&test_nonce(10)).context();
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);

    let mut second = V2Request::new(&test_nonce(11)).context();
    assert_continue(plugin.authenticate(&mut second, &consumer_index).await);
}

#[tokio::test]
async fn v2_new_nonce_without_recomputed_signature_fails_authentication() {
    let plugin = v2_plugin_named("v2-unsigned-nonce");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let request = V2Request::new(&test_nonce(20));
    let mut ctx = request.context();
    // Swap only the nonce, keeping the signature that covered the original one.
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &test_nonce(21), &request.signature),
    );
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
}

/// Every field the profile claims to bind must actually be bound: mutating one
/// without recomputing the signature fails authentication.
#[tokio::test]
async fn v2_binds_every_signed_field() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    // Method.
    let plugin = v2_plugin_named("v2-bind-method");
    let request = V2Request::new(&test_nonce(30));
    let mut ctx = request.context();
    ctx.method = "PUT".to_string();
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    // Path.
    let plugin = v2_plugin_named("v2-bind-path");
    let request = V2Request::new(&test_nonce(31));
    let mut ctx = request.context();
    ctx.path = "/api/other".to_string();
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    // Raw query.
    let plugin = v2_plugin_named("v2-bind-query");
    let request = V2Request::new(&test_nonce(32));
    let mut ctx = request.context();
    ctx.set_raw_query_string("admin=1".to_string());
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    // Date.
    let plugin = v2_plugin_named("v2-bind-date");
    let request = V2Request::new(&test_nonce(33));
    let mut ctx = request.context();
    ctx.headers.insert(
        "date".to_string(),
        (Utc::now() - chrono::Duration::seconds(30))
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string(),
    );
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    // Body digest.
    let plugin = v2_plugin_named("v2-bind-digest");
    let request = V2Request::new(&test_nonce(34));
    let mut ctx = request.context();
    ctx.headers
        .insert("digest".to_string(), sha256_digest_header(b"tampered"));
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    // Namespace (the protection domain the signature is scoped to).
    let plugin = v2_plugin_named("v2-bind-namespace");
    let request = V2Request::new(&test_nonce(35));
    let mut ctx = request.context();
    set_ctx_namespace(&mut ctx, "other-namespace");
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
}

/// A v1 signature must not verify under v2 (and the reverse): the profile
/// version is the signing base's first field, so downgrading the profile does
/// not downgrade the signature.
#[tokio::test]
async fn v1_signature_does_not_verify_under_v2() {
    let plugin = v2_plugin_named("v2-no-v1-crossover");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let method = "POST";
    let path = "/api/orders";
    let date = current_date();
    let digest = sha256_digest_header(b"");
    let v1_signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &test_nonce(40), &v1_signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    ctx.identified_consumer = None;
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
}

// ── nonce wire form ─────────────────────────────────────────────────

#[tokio::test]
async fn v2_rejects_a_missing_or_malformed_nonce_before_backend_dispatch() {
    let plugin = v2_plugin_named("v2-nonce-form");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let request = V2Request::new(&test_nonce(50));

    // Missing entirely.
    let mut ctx = request.context();
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &request.signature),
    );
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    for malformed in [
        "",                                // empty
        "short",                           // far below the entropy floor
        "0123456789abcdef0123456789abcde", // 31 hex chars: below 128 bits
        "0123456789abcdef0123456789abcd",  // 30 hex chars: below 128 bits
        "aaaaaaaaaaaaaaaaaaaaa",           // 21 base64url chars: below 128 bits
        "aaaa aaaaaaaaaaaaaaaaaaaaa",      // whitespace
        "aaaaaaaaaaaaaaaaaaaaaa\u{7f}",    // control byte
        "AAAAAAAAAAAAAAAAAAAAAA==",        // base64 padding is not base64url-unpadded
        "AAAAAAAAAAAAAAAAAAAAAA+/",        // standard-base64 alphabet
        &"a".repeat(87),                   // above the length ceiling
    ] {
        let mut ctx = request.context();
        ctx.headers.insert(
            "authorization".to_string(),
            v2_auth_header(TEST_USERNAME, malformed, &request.signature),
        );
        assert_reject(
            plugin.authenticate(&mut ctx, &consumer_index).await,
            Some(401),
        );
    }
}

/// An all-hex value is read as **hex** and held to the 32-character (128-bit)
/// floor, not to the shorter base64url floor. A 22-character all-hex nonce
/// satisfies the base64url length rule but carries only 88 bits, so admitting
/// it because "22 base64url characters would have been enough" would be a real
/// entropy downgrade.
#[tokio::test]
async fn all_hex_nonces_are_held_to_the_hex_entropy_floor() {
    let plugin = v2_plugin_named("v2-hex-floor");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let short_hex = "0123456789abcdef012345"; // 22 chars, all hex, 88 bits
    assert_eq!(short_hex.len(), 22);
    let request = V2Request::new(short_hex);
    let mut ctx = request.context();
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );

    // 22 non-hex base64url characters carry 132 bits and are admissible.
    let base64url = "zzzzzzzzzzzzzzzzzzzzzz";
    assert_eq!(base64url.len(), 22);
    let mut ctx = V2Request::new(base64url).context();
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
}

#[tokio::test]
async fn v1_rejects_a_nonce_rather_than_ignoring_it() {
    let plugin = HmacAuth::new(&default_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);

    let method = "POST";
    let path = "/api/orders";
    let date = current_date();
    let digest = sha256_digest_header(b"");
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);

    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &test_nonce(60), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);
    ctx.identified_consumer = None;
    assert_reject(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
}

// ── domain identity ─────────────────────────────────────────────────

/// An equivalent reload derives the same protection domain (so the replacement
/// instance inherits live markers), while a distinct policy id or namespace
/// isolates.
#[test]
fn v2_protection_domains_converge_on_reload_and_isolate_across_policies() {
    let first = v2_plugin_named("policy-a");
    let reloaded = v2_plugin_named("policy-a");
    let other_policy = v2_plugin_named("policy-b");
    let standalone = HmacAuth::new(&v2_config()).unwrap();

    let marker = first.replay_marker_digest("consumer-1", &test_nonce(70));
    assert_eq!(
        marker,
        reloaded.replay_marker_digest("consumer-1", &test_nonce(70))
    );
    assert_ne!(
        marker,
        other_policy.replay_marker_digest("consumer-1", &test_nonce(70))
    );
    assert_ne!(
        marker,
        standalone.replay_marker_digest("consumer-1", &test_nonce(70)),
        "a validation/standalone instance must not join a live policy's lane"
    );
    assert_ne!(
        marker,
        first.replay_marker_digest("consumer-2", &test_nonce(70)),
        "consumers must not burn one another's nonces"
    );
    assert!(
        HmacAuth::new(&default_config())
            .unwrap()
            .replay_marker_digest("consumer-1", &test_nonce(70))
            .is_none(),
        "the legacy profile has no replay domain at all"
    );
}

/// An equivalent reload must not reopen an already-claimed nonce: the
/// replacement instance joins the same lane rather than starting empty.
#[tokio::test]
async fn v2_replay_stays_rejected_after_an_equivalent_reload() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let request = V2Request::new(&test_nonce(80));

    let original = v2_plugin_named("v2-reload");
    let mut first = request.context();
    assert_continue(original.authenticate(&mut first, &consumer_index).await);

    // Retire the generation that made the claim and rebuild an equivalent one,
    // exactly as a plugin-cache rebuild does.
    drop(original);
    let reloaded = v2_plugin_named("v2-reload");
    let mut replay = request.context();
    assert_reject(
        reloaded.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// Two equivalent replicas (independently constructed, same policy identity)
/// share one process lane in this single-process test, which is exactly the
/// convergence a `shared` authority provides across processes.
#[tokio::test]
async fn v2_replay_is_rejected_across_equivalent_instances() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let request = V2Request::new(&test_nonce(90));

    let replica_a = v2_plugin_named("v2-replicas");
    let replica_b = v2_plugin_named("v2-replicas");

    let mut first = request.context();
    assert_continue(replica_a.authenticate(&mut first, &consumer_index).await);
    let mut replay = request.context();
    assert_reject(
        replica_b.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// An isolated policy must not answer from another policy's history.
#[tokio::test]
async fn v2_replay_lanes_are_isolated_across_policies() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let request = V2Request::new(&test_nonce(100));

    let policy_a = v2_plugin_named("v2-isolation-a");
    let policy_b = v2_plugin_named("v2-isolation-b");

    let mut first = request.context();
    assert_continue(policy_a.authenticate(&mut first, &consumer_index).await);
    let mut second = request.context();
    assert_continue(policy_b.authenticate(&mut second, &consumer_index).await);
}

/// Invalid traffic must never reach replay state: a request whose signature
/// does not verify is rejected, and the same nonce is then still claimable by
/// the legitimate signed request.
#[tokio::test]
async fn invalid_traffic_does_not_consume_replay_capacity() {
    let plugin = v2_plugin_named("v2-no-precharge");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let nonce = test_nonce(110);
    let request = V2Request::new(&nonce);

    // Same nonce, garbage signature.
    let mut forged = request.context();
    forged.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, "bm90LWEtc2lnbmF0dXJl"),
    );
    assert_reject(
        plugin.authenticate(&mut forged, &consumer_index).await,
        Some(401),
    );

    // The legitimate request carrying the same nonce still succeeds, proving
    // the forged attempt never wrote a marker.
    let mut legitimate = request.context();
    assert_continue(plugin.authenticate(&mut legitimate, &consumer_index).await);
}

// ── cross-instance prebuffer ownership ──────────────────────────────
//
// `hmac_auth` verifies the signature BEFORE request-body collection and stages
// the result on the request context, then completes the digest check after the
// body arrives. Several `hmac_auth` instances can screen one request — sibling
// proxy/global policies, a legacy v1 instance beside a v2 one, two v2 policies
// with different replay domains — so a single request-global staging slot would
// let one instance consume another's verified record. The worst shape is a v1
// instance consuming a v2 record: v1's claim path is a no-op, so the request
// would be accepted with no single-use guarantee at all. Every record is bound
// to the exact instance/policy/profile/replay-domain that staged it.

fn v1_plugin_named(config_id: &str) -> HmacAuth {
    HmacAuth::new_with_http_client_and_config_id(
        &default_config(),
        ferrum_edge::plugins::utils::PluginHttpClient::default(),
        Some(config_id),
    )
    .expect("acknowledged legacy v1 config")
}

/// How many preverified authorizations are staged on this request.
///
/// Read through `Debug`, which is exactly the redacted surface the production
/// type exposes: a count and nothing else — no owner, consumer, nonce, or
/// signature.
fn staged_prebuffer_records(ctx: &RequestContext) -> usize {
    const MARKER: &str = "HmacPrebufferState { staged: ";
    let rendered = format!("{ctx:?}");
    let start = rendered
        .find(MARKER)
        .expect("the request context renders its prebuffer state")
        + MARKER.len();
    let rest = &rendered[start..];
    let end = rest
        .find(' ')
        .expect("the staged count is followed by a space");
    rest[..end]
        .parse()
        .expect("the staged count renders as an integer")
}

/// A legacy v1 instance must not consume a v2 instance's preverified record.
///
/// This is the bypass the ownership binding exists to close: v1 makes no
/// single-use claim, so consuming a v2 record would accept a `ferrum-hmac-v2`
/// request without ever claiming its nonce — and the nonce would then still be
/// replayable.
#[tokio::test]
async fn a_v1_instance_cannot_consume_a_v2_instances_preverified_record() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let v2 = v2_plugin_named("owner-v2-first");
    let v1 = v1_plugin_named("owner-v1-sibling");
    let request = V2Request::new(&test_nonce(200));

    let mut ctx = request.context();
    assert!(
        v2.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
        "the v2 instance preverifies and stages"
    );
    assert!(
        !v1.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
        "a v2 nonce is not accepted by the v1 profile, so v1 stages nothing"
    );
    assert_eq!(staged_prebuffer_records(&ctx), 1);

    // The v1 instance runs first. It must not read the v2 record: it falls
    // through to its own extraction, which refuses the unexpected nonce.
    assert_reject(v1.authenticate(&mut ctx, &consumer_index).await, Some(401));
    assert!(
        ctx.identified_consumer.is_none(),
        "a refused instance must publish no identity"
    );
    assert_eq!(
        staged_prebuffer_records(&ctx),
        1,
        "one instance must not erase another owner's staged record"
    );

    // The owning v2 instance still finds its record and claims the nonce.
    assert_continue(v2.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(staged_prebuffer_records(&ctx), 0);

    // The claim really happened: the same signed request is now a replay.
    let mut replay = request.context();
    assert_reject(
        v2.authenticate(&mut replay, &consumer_index).await,
        Some(401),
    );
}

/// The reverse order: a v1 instance stages first, and the v2 instance must not
/// adopt that record — it would otherwise authenticate a v1-signed request under
/// the v2 profile with no nonce to claim.
#[tokio::test]
async fn a_v2_instance_cannot_consume_a_v1_instances_preverified_record() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let v1 = v1_plugin_named("owner-v1-first");
    let v2 = v2_plugin_named("owner-v2-sibling");

    // A v1-signed request: no nonce anywhere in the Authorization header.
    let method = "POST";
    let path = "/api/orders";
    let date = current_date();
    let digest = sha256_digest_header(b"");
    let signature = sign_sha256_with_digest(TEST_SECRET, method, path, &date, &digest);
    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        hmac_auth_header(TEST_USERNAME, Some("hmac-sha256"), &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("digest".to_string(), digest);

    assert!(
        v1.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
        "the v1 instance preverifies and stages"
    );
    assert!(
        !v2.should_buffer_request_body_before_authenticate(&ctx, &consumer_index),
        "the v2 profile requires a nonce, so it stages nothing here"
    );
    assert_eq!(staged_prebuffer_records(&ctx), 1);

    assert_reject(v2.authenticate(&mut ctx, &consumer_index).await, Some(401));
    assert_eq!(
        staged_prebuffer_records(&ctx),
        1,
        "the v2 instance must not consume or erase the v1 owner's record"
    );

    assert_continue(v1.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(staged_prebuffer_records(&ctx), 0);
}

/// Two sibling v2 policies on one request: each stages and consumes only its
/// own record, and each claims in its own replay domain. Neither may skip its
/// own verification by adopting the other's, and neither may erase the other's.
#[tokio::test]
async fn sibling_v2_policies_stage_and_consume_independently() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let policy_a = v2_plugin_named("owner-sibling-a");
    let policy_b = v2_plugin_named("owner-sibling-b");
    let request = V2Request::new(&test_nonce(201));

    let mut ctx = request.context();
    assert!(policy_a.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));
    assert!(policy_b.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));
    assert_eq!(
        staged_prebuffer_records(&ctx),
        2,
        "each policy owns its own slot"
    );

    assert_continue(policy_a.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(
        staged_prebuffer_records(&ctx),
        1,
        "policy A consumed exactly its own record"
    );
    assert_continue(policy_b.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(staged_prebuffer_records(&ctx), 0);

    // Both policies claimed in their own domains, so both now see a replay.
    let mut replay_a = request.context();
    assert_reject(
        policy_a.authenticate(&mut replay_a, &consumer_index).await,
        Some(401),
    );
    let mut replay_b = request.context();
    assert_reject(
        policy_b.authenticate(&mut replay_b, &consumer_index).await,
        Some(401),
    );
}

/// A staged record is not consumed when the request changed under it, and the
/// refusal must not leave a foreign owner's record behind either.
#[tokio::test]
async fn a_staged_record_is_not_consumed_when_the_request_changed() {
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let owner = v2_plugin_named("owner-binding-mismatch");
    let sibling = v2_plugin_named("owner-binding-sibling");
    let request = V2Request::new(&test_nonce(202));

    let mut ctx = request.context();
    assert!(owner.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));
    assert!(sibling.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));

    // Rewrite the Authorization header after staging. The owner's record no
    // longer binds this request, so it must be discarded rather than trusted.
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &test_nonce(203), &request.signature),
    );
    assert_reject(
        owner.authenticate(&mut ctx, &consumer_index).await,
        Some(401),
    );
    assert!(ctx.identified_consumer.is_none());
    assert_eq!(
        staged_prebuffer_records(&ctx),
        1,
        "only the owner's own record was discarded"
    );

    // The nonce the owner staged was never claimed, so the legitimate signed
    // request still succeeds.
    let mut legitimate = request.context();
    assert_continue(owner.authenticate(&mut legitimate, &consumer_index).await);
}

// ────────────────────────────────────────────────────────────────────
// Issue #3932 — Content-Digest + ferrum-hmac-v2 signing contract
// ────────────────────────────────────────────────────────────────────

fn sign_v2_with_digest(
    secret: &str,
    method: &str,
    path: &str,
    date: &str,
    digest: &str,
    nonce: &str,
) -> String {
    sign_v2(
        secret,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: TEST_USERNAME,
            authority: TEST_AUTHORITY,
            method,
            path,
            query: "",
            date,
            digest_header: digest,
        },
        nonce,
    )
}

async fn authenticate_v2_digest_request(
    digest: &str,
    content_digest: bool,
    body: &[u8],
    hashes_present: bool,
    nonce_seed: u64,
) -> (PluginResult, RequestContext) {
    let plugin = v2_plugin_named(&format!("v2-digest-{nonce_seed}"));
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let method = "POST";
    let path = "/api/orders";
    let date = current_date();
    let nonce = test_nonce(nonce_seed);
    let signature = sign_v2_with_digest(TEST_SECRET, method, path, &date, digest, &nonce);
    let mut ctx = make_ctx(method, path);
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    if content_digest {
        set_content_digest(&mut ctx, digest.to_string());
    } else {
        set_legacy_digest(&mut ctx, digest.to_string());
    }
    if hashes_present {
        set_request_body(&mut ctx, body);
    } else {
        ctx.request_body_sha256 = None;
        ctx.request_body_sha512 = None;
    }
    ctx.identified_consumer = None;
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    (result, ctx)
}

#[tokio::test]
async fn v2_accepts_rfc9530_content_digest_for_nonempty_body() {
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let (result, ctx) = authenticate_v2_digest_request(&digest, true, body, true, 3932).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
}

#[tokio::test]
async fn v2_accepts_rfc9530_content_digest_for_empty_body() {
    let body = b"";
    let digest = sha256_content_digest_header(body);
    let (result, ctx) = authenticate_v2_digest_request(&digest, true, body, true, 3933).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
}

#[tokio::test]
async fn v2_accepts_legacy_digest_for_nonempty_and_empty_bodies() {
    for (seed, body) in [(3934u64, &br#"{"ping":1}"#[..]), (3935, &b""[..])] {
        let digest = sha256_digest_header(body);
        let (result, ctx) = authenticate_v2_digest_request(&digest, false, body, true, seed).await;
        assert_continue(result);
        assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
    }
}

#[tokio::test]
async fn v2_rejects_bad_digest_without_accepting_the_signature() {
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(b"not-the-body");
    let (result, ctx) = authenticate_v2_digest_request(&digest, true, body, true, 3936).await;
    assert_reject_error(result, 401, "Digest header does not match request body");
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn v2_rejects_bad_signature_as_invalid_credentials() {
    let plugin = v2_plugin_named("v2-bad-sig");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3937);
    let signature = sign_v2_with_digest(
        "wrong-secret-that-cannot-authenticate-hmac",
        "POST",
        "/api/orders",
        &date,
        &digest,
        &nonce,
    );
    let mut ctx = make_ctx("POST", "/api/orders");
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    set_content_digest(&mut ctx, digest);
    set_request_body(&mut ctx, body);
    assert_reject_error(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        401,
        "Invalid credentials",
    );
}

#[tokio::test]
async fn missing_body_hashes_do_not_impersonate_an_empty_body() {
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let (result, ctx) = authenticate_v2_digest_request(&digest, true, body, false, 3938).await;
    assert_reject_error(result, 401, "Digest header does not match request body");
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn missing_body_hashes_with_invalid_signature_are_invalid_credentials() {
    let plugin = v2_plugin_named("v2-no-hash-bad-sig");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3939);
    let signature = sign_v2_with_digest(
        "wrong-secret-that-cannot-authenticate-hmac",
        "POST",
        "/api/orders",
        &date,
        &digest,
        &nonce,
    );
    let mut ctx = make_ctx("POST", "/api/orders");
    ctx.request_body_sha256 = None;
    ctx.request_body_sha512 = None;
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    set_content_digest(&mut ctx, digest);
    assert_reject_error(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        401,
        "Invalid credentials",
    );
}

#[tokio::test]
async fn both_digest_headers_fail_closed_as_ambiguous() {
    let plugin = v2_plugin_named("v2-ambiguous-digest");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let content = sha256_content_digest_header(body);
    let legacy = sha256_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3940);
    let signature =
        sign_v2_with_digest(TEST_SECRET, "POST", "/api/orders", &date, &content, &nonce);
    let mut ctx = make_ctx("POST", "/api/orders");
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    ctx.headers.insert("content-digest".to_string(), content);
    ctx.headers.insert("digest".to_string(), legacy);
    set_request_body(&mut ctx, body);
    assert_reject_error(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        401,
        "Ambiguous Digest and Content-Digest headers",
    );
}

#[tokio::test]
async fn repeated_valid_content_digest_field_lines_are_folded_and_verified() {
    let plugin = v2_plugin_named("v2-repeated-valid-content-digest");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let sha256 = sha256_content_digest_header(body);
    let sha512 = sha512_content_digest_header(body);
    let folded_digest = format!("{sha256}, {sha512}");
    let date = current_date();
    let nonce = test_nonce(3948);
    let signature = sign_v2_with_digest(
        TEST_SECRET,
        "POST",
        "/api/orders",
        &date,
        &folded_digest,
        &nonce,
    );
    let authorization = v2_auth_header(TEST_USERNAME, &nonce, &signature);

    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "content-digest",
        http::HeaderValue::from_str(&sha256).unwrap(),
    );
    raw_headers.append(
        "content-digest",
        http::HeaderValue::from_str(&sha512).unwrap(),
    );
    raw_headers.insert(
        "authorization",
        http::HeaderValue::from_str(&authorization).unwrap(),
    );
    raw_headers.insert("date", http::HeaderValue::from_str(&date).unwrap());

    let mut ctx = make_ctx("POST", "/api/orders");
    ctx.headers.clear();
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    set_request_body(&mut ctx, body);
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
}

#[tokio::test]
async fn non_utf8_duplicate_digest_field_line_fails_closed() {
    let plugin = v2_plugin_named("v2-non-utf8-content-digest");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3949);
    let signature = sign_v2_with_digest(TEST_SECRET, "POST", "/api/orders", &date, &digest, &nonce);
    let authorization = v2_auth_header(TEST_USERNAME, &nonce, &signature);

    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "content-digest",
        http::HeaderValue::from_str(&digest).unwrap(),
    );
    raw_headers.append(
        "content-digest",
        http::HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
    raw_headers.insert(
        "authorization",
        http::HeaderValue::from_str(&authorization).unwrap(),
    );
    raw_headers.insert("date", http::HeaderValue::from_str(&date).unwrap());

    let mut ctx = make_ctx("POST", "/api/orders");
    ctx.headers.clear();
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    set_request_body(&mut ctx, body);
    assert_reject_error(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        401,
        "Malformed digest header",
    );
}

#[tokio::test]
async fn unsupported_and_malformed_digest_headers_fail_closed() {
    let plugin = v2_plugin_named("v2-digest-shape");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let date = current_date();
    let nonce = test_nonce(3941);
    let signature = sign_v2_with_digest(
        TEST_SECRET,
        "POST",
        "/api/orders",
        &date,
        "sha-256=aaaa",
        &nonce,
    );

    let mut unsupported = make_ctx("POST", "/api/orders");
    unsupported.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    unsupported.headers.insert("date".to_string(), date.clone());
    set_legacy_digest(&mut unsupported, "md5=ignored".to_string());
    assert_reject_error(
        plugin.authenticate(&mut unsupported, &consumer_index).await,
        401,
        "Unsupported digest algorithm",
    );

    let mut malformed = make_ctx("POST", "/api/orders");
    malformed.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    malformed.headers.insert("date".to_string(), date);
    set_content_digest(&mut malformed, "sha-256=not-a-byte-sequence".to_string());
    assert_reject_error(
        plugin.authenticate(&mut malformed, &consumer_index).await,
        401,
        "Malformed digest header",
    );
}

#[tokio::test]
async fn v2_accepts_combined_rfc9530_sha256_and_sha512_when_both_match() {
    let body = br#"{"ping":1}"#;
    let digest = format!(
        "{}, {}",
        sha256_content_digest_header(body),
        sha512_content_digest_header(body)
    );
    let (result, ctx) = authenticate_v2_digest_request(&digest, true, body, true, 3945).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
}

#[tokio::test]
async fn v2_rejects_when_one_of_two_digest_algorithms_mismatches() {
    let body = br#"{"ping":1}"#;
    let digest = format!(
        "{}, {}",
        sha256_content_digest_header(body),
        sha512_content_digest_header(b"not-the-body")
    );
    let (result, ctx) = authenticate_v2_digest_request(&digest, true, body, true, 3946).await;
    assert_reject_error(result, 401, "Digest header does not match request body");
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn v2_rejects_duplicate_digest_algorithm_keys_and_mixed_spellings() {
    let plugin = v2_plugin_named("v2-digest-duplicates");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let date = current_date();
    let nonce = test_nonce(3947);
    let single = sha256_content_digest_header(body);
    let signature = sign_v2_with_digest(TEST_SECRET, "POST", "/api/orders", &date, &single, &nonce);

    let mut duplicate = make_ctx("POST", "/api/orders");
    duplicate.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    duplicate.headers.insert("date".to_string(), date.clone());
    set_content_digest(&mut duplicate, format!("{single}, {single}"));
    set_request_body(&mut duplicate, body);
    assert_reject_error(
        plugin.authenticate(&mut duplicate, &consumer_index).await,
        401,
        "Malformed digest header",
    );

    let mixed = format!("{}, {}", single, sha512_digest_header(body));
    let mut mixed_ctx = make_ctx("POST", "/api/orders");
    mixed_ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    mixed_ctx.headers.insert("date".to_string(), date);
    set_content_digest(&mut mixed_ctx, mixed);
    set_request_body(&mut mixed_ctx, body);
    assert_reject_error(
        plugin.authenticate(&mut mixed_ctx, &consumer_index).await,
        401,
        "Malformed digest header",
    );
}

#[tokio::test]
async fn v2_replay_of_a_content_digest_request_is_rejected() {
    let plugin = v2_plugin_named("v2-content-digest-replay");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3942);
    let signature = sign_v2_with_digest(TEST_SECRET, "POST", "/api/orders", &date, &digest, &nonce);

    let mut first = make_ctx("POST", "/api/orders");
    first.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    first.headers.insert("date".to_string(), date.clone());
    set_content_digest(&mut first, digest.clone());
    set_request_body(&mut first, body);
    assert_continue(plugin.authenticate(&mut first, &consumer_index).await);

    let mut replay = make_ctx("POST", "/api/orders");
    replay.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    replay.headers.insert("date".to_string(), date);
    set_content_digest(&mut replay, digest);
    set_request_body(&mut replay, body);
    assert_reject_error(
        plugin.authenticate(&mut replay, &consumer_index).await,
        401,
        "Signed request has already been used",
    );
}

#[tokio::test]
async fn hmac_auth_preserves_downstream_request_body_bytes() {
    let plugin = v2_plugin_named("v2-preserve-body");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"ping":1}"#;
    let digest = sha256_content_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3943);
    let signature = sign_v2_with_digest(TEST_SECRET, "POST", "/api/orders", &date, &digest, &nonce);
    let mut ctx = make_ctx("POST", "/api/orders");
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    set_content_digest(&mut ctx, digest);
    set_request_body(&mut ctx, body);
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(body));
    ctx.identified_consumer = None;

    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(
        ctx.request_body_bytes.as_deref(),
        Some(body.as_slice()),
        "hmac_auth must not rewrite the forwarding buffer"
    );
    assert!(
        !ctx.metadata.contains_key("request_body"),
        "hmac_auth must not retain a UTF-8 body copy"
    );
    ctx.set_raw_query_string("access_token=debug-secret".to_string());
    let credential_debug = format!("{:?}", plugin.extract(&ctx));
    assert!(
        credential_debug.contains("[REDACTED]"),
        "extracted HMAC credential debug must redact signature material"
    );
    assert!(
        !credential_debug.contains("ping"),
        "extracted HMAC credential debug must not include body content"
    );
    assert!(
        !credential_debug.contains(&signature),
        "extracted HMAC credential debug must not include the signature bytes"
    );
    assert!(
        !credential_debug.contains("debug-secret"),
        "extracted HMAC credential debug must not include raw query credentials"
    );
}

#[tokio::test]
async fn hmac_prebuffer_then_matching_rfc9530_body_authenticates() {
    let plugin = v2_plugin_named("v2-prebuffer-content-digest");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let body = br#"{"amount":1}"#;
    let digest = sha256_content_digest_header(body);
    let date = current_date();
    let nonce = test_nonce(3944);
    let signature = sign_v2_with_digest(TEST_SECRET, "POST", "/upload", &date, &digest, &nonce);

    let mut ctx = make_ctx("POST", "/upload");
    ctx.request_body_sha256 = None;
    ctx.request_body_sha512 = None;
    ctx.headers.insert(
        "authorization".to_string(),
        v2_auth_header(TEST_USERNAME, &nonce, &signature),
    );
    ctx.headers.insert("date".to_string(), date);
    set_content_digest(&mut ctx, digest);
    assert!(plugin.should_buffer_request_body_before_authenticate(&ctx, &consumer_index));
    set_request_body(&mut ctx, body);
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(ctx.identified_consumer.unwrap().username, TEST_USERNAME);
}

#[tokio::test]
async fn test_hmac_auth_non_ascii_authorization_returns_invalid_not_missing() {
    let plugin = HmacAuth::new(&v2_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = context_with_materialized_raw_header(
        "Authorization",
        &format!(
            "hmac username=\"{TEST_USERNAME}\", algorithm=\"hmac-sha256\", \
             nonce=\"01234567890123456789012345678901\", signature=\"dGVzdA==\"\u{3000}"
        ),
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid Authorization header"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_hmac_auth_non_ascii_digest_returns_invalid_not_missing() {
    let plugin = HmacAuth::new(&v2_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = make_ctx("GET", "/test");
    ctx.headers.clear();
    ctx.identified_consumer = None;
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    ctx.headers.insert(
        "authorization".to_string(),
        format!(
            "hmac username=\"{TEST_USERNAME}\", algorithm=\"hmac-sha256\", \
             nonce=\"01234567890123456789012345678901\", signature=\"dGVzdA==\""
        ),
    );

    let mut digest_value = sha256_digest_header(&[]).into_bytes();
    digest_value.push(0xC2);
    digest_value.push(0x80);

    let mut raw = http::HeaderMap::new();
    raw.insert(
        "digest",
        http::HeaderValue::from_bytes(&digest_value).expect("valid header bytes"),
    );
    ctx.set_raw_headers(raw);
    ctx.materialize_headers();
    // Valid UTF-8 obs-text is materialized byte-for-byte (issue #5010); the
    // digest grammar is still visible-ASCII only, so the value is malformed
    // rather than missing.
    assert!(ctx.headers.contains_key("digest"));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Malformed digest header"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_hmac_auth_invalid_utf8_authorization_returns_invalid_not_missing() {
    let plugin = HmacAuth::new(&v2_config()).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = context_with_materialized_raw_header_bytes(
        "Authorization",
        b"hmac username=\"x\", nonce=\"01234567890123456789012345678901\", signature=\"dGVzdA==\"\xff",
    );
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid Authorization header"}"#);
    assert!(ctx.identified_consumer.is_none());
}

// ── Issue #5000: a signed WebSocket handshake must authenticate ─────────────
//
// WebSocket streams are categorically excluded from request-body collection —
// after the upgrade, DATA is tunnel payload, not an HTTP request body — so the
// digest snapshots were absent on every WebSocket route. Absent snapshots MUST
// fail closed, so every correctly signed handshake was answered 401 with a
// digest mismatch even though the plugin declares WebSocket support.
//
// The handshake itself declares no body on the wire, so the transport publishes
// exactly that proof before the authenticate phase. These tests drive the same
// helper the H1/H2 and H3 ladders call.

/// Drive the transport-owned handshake proof the dispatchers publish.
fn publish_handshake_proof(plugins: &[Arc<dyn Plugin>], ctx: &mut RequestContext) {
    ferrum_edge::_test_support::publish_websocket_handshake_body_digests_for_test(plugins, ctx);
}

fn ws_plugins(config_id: &str) -> Vec<Arc<dyn Plugin>> {
    vec![Arc::new(v2_plugin_named(config_id))]
}

/// A `ferrum-hmac-v2` handshake signed over the empty body.
fn v2_websocket_request(nonce: &str) -> V2Request {
    let method = "GET".to_string();
    let path = "/socket".to_string();
    let date = current_date();
    let digest = sha256_digest_header(b"");
    let signature = sign_v2(
        TEST_SECRET,
        HmacSigningInput {
            namespace: ferrum_edge::config::types::DEFAULT_NAMESPACE,
            username: TEST_USERNAME,
            authority: TEST_AUTHORITY,
            method: &method,
            path: &path,
            query: "",
            date: &date,
            digest_header: &digest,
        },
        nonce,
    );
    V2Request {
        method,
        path,
        date,
        digest,
        nonce: nonce.to_string(),
        signature,
    }
}

/// A handshake context with the digest snapshots absent, as the WebSocket
/// dispatchers leave them.
fn websocket_handshake_context(request: &V2Request) -> RequestContext {
    let mut ctx = request.context();
    ctx.request_body_sha256 = None;
    ctx.request_body_sha512 = None;
    ctx
}

#[tokio::test]
async fn websocket_handshake_without_the_transport_proof_still_fails_closed() {
    // Non-vacuity for the test below: absent snapshots are a refusal, and the
    // fix is the transport publishing the proof — not the plugin relaxing.
    let plugin = v2_plugin_named("v2-ws-no-proof");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let mut ctx = websocket_handshake_context(&v2_websocket_request(&test_nonce(0x5000)));

    assert_reject_error(
        plugin.authenticate(&mut ctx, &consumer_index).await,
        401,
        "Digest header does not match request body",
    );
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn websocket_handshake_authenticates_with_the_transport_empty_body_proof() {
    let plugins = ws_plugins("v2-ws-proof");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let mut ctx = websocket_handshake_context(&v2_websocket_request(&test_nonce(0x5001)));

    publish_handshake_proof(&plugins, &mut ctx);
    assert!(ctx.request_body_sha256.is_some());
    assert!(ctx.request_body_sha512.is_some());

    assert_continue(plugins[0].authenticate(&mut ctx, &consumer_index).await);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        TEST_USERNAME
    );
    assert_eq!(ctx.auth_method, Some("hmac_auth"));
}

#[tokio::test]
async fn websocket_handshake_replay_is_still_rejected_before_the_backend() {
    let plugins = ws_plugins("v2-ws-replay");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let request = v2_websocket_request(&test_nonce(0x5002));

    let mut first = websocket_handshake_context(&request);
    publish_handshake_proof(&plugins, &mut first);
    assert_continue(plugins[0].authenticate(&mut first, &consumer_index).await);

    let mut replay = websocket_handshake_context(&request);
    publish_handshake_proof(&plugins, &mut replay);
    let result = plugins[0].authenticate(&mut replay, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(replay.identified_consumer.is_none());
}

#[tokio::test]
async fn websocket_handshake_with_an_altered_digest_is_rejected() {
    let plugins = ws_plugins("v2-ws-altered");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let mut ctx = websocket_handshake_context(&v2_websocket_request(&test_nonce(0x5003)));
    ctx.headers
        .insert("digest".to_string(), sha256_digest_header(b"not-the-body"));

    publish_handshake_proof(&plugins, &mut ctx);
    let result = plugins[0].authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn websocket_handshake_with_an_invalid_signature_is_rejected() {
    let plugins = ws_plugins("v2-ws-bad-sig");
    let consumer_index = ConsumerIndex::new(&[create_hmac_consumer()]);
    let mut request = v2_websocket_request(&test_nonce(0x5004));
    request.signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
    let mut ctx = websocket_handshake_context(&request);

    publish_handshake_proof(&plugins, &mut ctx);
    assert_reject_error(
        plugins[0].authenticate(&mut ctx, &consumer_index).await,
        401,
        "Invalid credentials",
    );
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn the_handshake_proof_is_withheld_when_the_request_declares_a_body() {
    // Fails closed on anything that is not provably an empty handshake body.
    let plugins = ws_plugins("v2-ws-declared-body");

    for (name, value) in [("content-length", "5"), ("transfer-encoding", "chunked")] {
        let mut ctx = websocket_handshake_context(&v2_websocket_request(&test_nonce(0x5005)));
        ctx.headers.insert(name.to_string(), value.to_string());
        publish_handshake_proof(&plugins, &mut ctx);
        assert!(
            ctx.request_body_sha256.is_none() && ctx.request_body_sha512.is_none(),
            "a declared body must keep the snapshots absent: {name}: {value}"
        );
    }

    // `Content-Length: 0` is provably empty and still gets the proof.
    let mut zero = websocket_handshake_context(&v2_websocket_request(&test_nonce(0x5006)));
    zero.headers
        .insert("content-length".to_string(), "0".to_string());
    publish_handshake_proof(&plugins, &mut zero);
    assert!(zero.request_body_sha256.is_some());
}

#[test]
fn the_handshake_proof_is_not_published_without_a_digest_consuming_plugin() {
    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let mut ctx = websocket_handshake_context(&v2_websocket_request(&test_nonce(0x5007)));

    publish_handshake_proof(&plugins, &mut ctx);

    assert!(ctx.request_body_sha256.is_none());
    assert!(ctx.request_body_sha512.is_none());
}

#[tokio::test]
async fn the_handshake_proof_never_overwrites_collected_body_hashes() {
    let plugins = ws_plugins("v2-ws-collected");
    let body = br#"{"ping":1}"#;
    let expected: [u8; 32] = Sha256::digest(body).into();
    let mut ctx = v2_websocket_request(&test_nonce(0x5008)).context();
    ctx.request_body_sha256 = Some(expected);
    ctx.request_body_sha512 = Some(Sha512::digest(body).into());

    publish_handshake_proof(&plugins, &mut ctx);

    assert_eq!(ctx.request_body_sha256, Some(expected));
}
