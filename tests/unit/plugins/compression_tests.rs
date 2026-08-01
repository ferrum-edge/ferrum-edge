// These tests intentionally serialize complete async cache lifecycles against
// process-global RTDS publications. The guard is test-only and no task in the
// guarded lifecycle reacquires it.
#![allow(clippy::await_holding_lock)]

use super::plugin_utils::create_test_proxy;
use ferrum_edge::_test_support::{
    apply_buffered_request_body_normalization_before_before_proxy_for_test,
    apply_buffered_request_body_normalization_with_requirements_for_test,
    apply_synthetic_response_body_hooks_for_test,
    discard_grpc_application_trailers_after_body_rewrite_for_test,
    finalize_plugin_rejection_parts_for_test, run_after_proxy_hooks_reject_for_test,
    set_response_presentation_policy_digest_for_test, stamp_original_response_metadata_for_test,
    transform_buffered_response_body_with_deadline_full_for_test,
};
use ferrum_edge::plugins::compression::{COMPRESSION_CONFIG_KEYS, CompressionPlugin};
use ferrum_edge::plugins::response_caching::ResponseCaching;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, validate_plugin_config};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// Origin integrity fields that become stale after gateway compression.
const INTEGRITY_DIGEST_HEADERS: &[&str] =
    &["content-digest", "repr-digest", "digest", "content-md5"];

fn insert_stale_integrity_digests(headers: &mut HashMap<String, String>) {
    // Mixed-case names prove case-insensitive cleanup rather than exact-key deletes.
    headers.insert(
        "Content-Digest".to_string(),
        "sha-256=:stale-content:".to_string(),
    );
    headers.insert(
        "Repr-Digest".to_string(),
        "sha-256=:stale-repr:".to_string(),
    );
    headers.insert("Digest".to_string(), "sha-256=stale-legacy".to_string());
    headers.insert("Content-MD5".to_string(), "stale-md5".to_string());
}

fn assert_integrity_digests_absent(headers: &HashMap<String, String>) {
    for name in INTEGRITY_DIGEST_HEADERS {
        assert!(
            headers.keys().all(|key| !key.eq_ignore_ascii_case(name)),
            "stale integrity field {name} must be removed after compression"
        );
    }
}

fn assert_integrity_digests_present(headers: &HashMap<String, String>) {
    for name in INTEGRITY_DIGEST_HEADERS {
        assert!(
            headers.keys().any(|key| key.eq_ignore_ascii_case(name)),
            "integrity field {name} must be preserved when compression does not rewrite bytes"
        );
    }
}

fn compressible_json_body() -> Vec<u8> {
    br#"{"users":[{"name":"alice","email":"alice@example.com","role":"admin"},{"name":"bob","email":"bob@example.com","role":"user"},{"name":"charlie","email":"charlie@example.com","role":"user"},{"name":"dave","email":"dave@example.com","role":"moderator"},{"name":"eve","email":"eve@example.com","role":"user"}]}"#
        .to_vec()
}

fn make_plugin(config: serde_json::Value) -> CompressionPlugin {
    CompressionPlugin::new(&config).unwrap()
}

/// Stand in for the proxy's transport-owned empty-request-body proof, which
/// `response_caching` requires before it may look up or store. These chains are
/// driven directly rather than through a proxy body-drain path.
fn prove_empty_request_body(ctx: &mut RequestContext) {
    ferrum_edge::_test_support::set_replay_request_body_empty_proven_for_test(ctx, true);
}

fn make_ctx(accept_encoding: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    ctx.max_response_body_size_bytes = 10 * 1024 * 1024;
    if let Some(ae) = accept_encoding {
        ctx.headers
            .insert("accept-encoding".to_string(), ae.to_string());
    }
    ctx
}

async fn plan_response_algorithm(
    plugin: &CompressionPlugin,
    ctx: &mut RequestContext,
    response_headers: &mut HashMap<String, String>,
    encoding: &str,
) {
    ctx.headers
        .insert("accept-encoding".to_string(), encoding.to_string());
    response_headers
        .entry("content-type".to_string())
        .or_insert_with(|| "application/json".to_string());
    assert!(matches!(
        plugin.after_proxy(ctx, 200, response_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        response_headers.get("content-encoding").map(String::as_str),
        Some(encoding)
    );
}

// ────────────────────── Config defaults ──────────────────────

/// Serialize against RTDS runtime-overlay publications.
///
/// `response_caching` stamps every stored entry with the live response-side
/// runtime-overlay gate fingerprint and retires entries whose stamp no longer
/// matches, so an overlay publication in a concurrently running test would
/// legitimately turn a HIT into a MISS. Every test that stores an entry and
/// then asserts a HIT/REVALIDATED replay takes this process-wide lock, which
/// is the same lock every overlay publisher holds.
fn response_cache_replay_policy_guard() -> std::sync::MutexGuard<'static, ()> {
    ferrum_edge::modes::mesh::runtime_overlay_consumers::test_lock()
}

fn seed_response_cache_presentation_policy(ctx: &mut RequestContext) {
    set_response_presentation_policy_digest_for_test(ctx, Some([0x51; 32]));
}

#[test]
fn test_default_config() {
    let plugin = make_plugin(json!({}));
    assert_eq!(plugin.name(), "compression");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::COMPRESSION
    );
    assert!(plugin.requires_response_body_buffering());
    assert!(!plugin.modifies_request_body()); // decompress_request defaults false
}

#[test]
fn test_null_config_uses_defaults() {
    let plugin =
        CompressionPlugin::new(&serde_json::Value::Null).expect("null config should use defaults");
    assert_eq!(plugin.name(), "compression");
    assert!(plugin.requires_response_body_buffering());
    assert!(!plugin.modifies_request_body());
}

#[test]
fn test_decompress_request_config() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    assert!(plugin.modifies_request_body());
    assert!(plugin.modifies_request_headers());
}

#[test]
fn test_global_algorithm_gates_intersect_response_and_request_support() {
    let plugin = CompressionPlugin::new_with_algorithm_support(
        &json!({"algorithms": ["gzip", "br"], "decompress_request": true}),
        false,
        true,
    )
    .expect("Brotli remains enabled");
    assert!(plugin.requires_response_body_buffering());

    let mut gzip_ctx = make_ctx(None);
    gzip_ctx
        .headers
        .insert("content-encoding".to_string(), "gzip".to_string());
    assert!(
        !plugin.should_buffer_request_body(&gzip_ctx),
        "globally disabled gzip must not buffer or decode requests"
    );

    let mut br_ctx = make_ctx(None);
    br_ctx
        .headers
        .insert("content-encoding".to_string(), "br".to_string());
    assert!(
        plugin.should_buffer_request_body(&br_ctx),
        "globally enabled Brotli remains available for request decoding"
    );

    let disabled = CompressionPlugin::new_with_algorithm_support(
        &json!({"algorithms": ["gzip", "br"], "decompress_request": true}),
        false,
        false,
    );
    let err = match disabled {
        Err(err) => err,
        Ok(_) => panic!("all-disabled global gates must fail admission"),
    };
    assert!(
        err.contains("no usable algorithms after applying process-wide codec gates"),
        "got: {err}"
    );

    let default_policy = make_plugin(json!({"decompress_request": true}));
    let mut x_gzip_ctx = make_ctx(None);
    x_gzip_ctx
        .headers
        .insert("content-encoding".to_string(), "x-gzip".to_string());
    assert!(
        default_policy.should_buffer_request_body(&x_gzip_ctx),
        "legacy x-gzip requests must use the canonical gzip decoder"
    );
}

#[test]
fn test_applies_after_proxy_on_reject() {
    let plugin = make_plugin(json!({}));
    assert!(plugin.applies_after_proxy_on_reject());
    assert!(plugin.may_replace_rejection_response());
    assert!(!plugin.warn_on_rejection_response_replacement());
}

#[test]
fn test_non_object_config_rejected() {
    let err = CompressionPlugin::new(&json!("bad"))
        .err()
        .expect("non-object config must be rejected");
    assert!(err.contains("config must be an object"), "got: {}", err);
}

#[test]
fn test_invalid_bool_config_rejected() {
    let err = CompressionPlugin::new(&json!({"decompress_request": "true"}))
        .err()
        .expect("bad bool config must be rejected");
    assert!(err.contains("decompress_request"), "got: {}", err);
}

#[test]
fn test_removed_disable_on_etag_config_rejected() {
    let err = CompressionPlugin::new(&json!({"disable_on_etag": false}))
        .err()
        .expect("removed ETag config must be rejected");
    assert!(
        err.contains("disable_on_etag") && err.contains("removed"),
        "got: {err}"
    );
    assert!(
        !err.contains("unknown configuration key"),
        "removed-key diagnostic must win over the generic unknown-key gate: {err}"
    );
}

#[test]
fn test_rejects_one_unknown_key_with_spelling_suggestion() {
    let err = CompressionPlugin::new(&json!({"min_content_lenght": 4096}))
        .err()
        .expect("typo key must be rejected");
    assert!(
        err.contains("unknown configuration key"),
        "missing unknown-key wording: {err}"
    );
    assert!(
        err.contains("'config.min_content_lenght'"),
        "path-qualified key missing: {err}"
    );
    assert!(
        err.contains("did you mean 'min_content_length'?"),
        "spelling suggestion missing: {err}"
    );

    let shared = validate_plugin_config("compression", &json!({"gzip_leveel": 1}))
        .expect_err("shared file/admin/database/CP-DP admission must reject the typo");
    assert!(
        shared.contains("'config.gzip_leveel'") && shared.contains("did you mean 'gzip_level'?"),
        "got: {shared}"
    );
}

#[test]
fn test_rejects_multiple_unknown_keys_deterministically() {
    let err = CompressionPlugin::new(&json!({
        "zzz_extra": true,
        "remove_accept_encodng": false,
        "aaa_extra": 1,
        "algorithms": ["gzip"]
    }))
    .err()
    .expect("multiple unknown keys must be rejected");
    assert!(
        err.contains("unknown configuration key(s): 'config.aaa_extra', 'config.remove_accept_encodng' (did you mean 'remove_accept_encoding'?), 'config.zzz_extra'"),
        "unexpected multi-key diagnostic: {err}"
    );

    let shared = validate_plugin_config(
        "compression",
        &json!({
            "zzz_extra": true,
            "remove_accept_encodng": false,
            "aaa_extra": 1
        }),
    )
    .expect_err("shared admission must reject the same multi-key set");
    assert_eq!(shared, err, "constructor and shared admission must match");
}

#[test]
fn test_accepts_every_valid_config_field() {
    let config = json!({
        "algorithms": ["gzip", "br"],
        "brotli_quality": 4,
        "content_types": ["application/json", "text/plain"],
        "decompress_request": true,
        "gzip_level": 6,
        "max_decompressed_request_size": 1_048_576,
        "min_content_length": 512,
        "remove_accept_encoding": false
    });
    let present: std::collections::BTreeSet<&str> = config
        .as_object()
        .expect("fixture object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: std::collections::BTreeSet<&str> =
        COMPRESSION_CONFIG_KEYS.iter().copied().collect();
    assert_eq!(
        present, expected,
        "fixture must exercise every accepted root field"
    );

    let plugin = CompressionPlugin::new(&config).expect("complete valid config must construct");
    assert!(plugin.modifies_request_body());
    assert!(plugin.requires_response_body_buffering());
    assert!(validate_plugin_config("compression", &config).is_ok());
}

#[test]
fn test_invalid_content_types_config_rejected() {
    let err = CompressionPlugin::new(&json!({"content_types": ["text/plain", 42]}))
        .err()
        .expect("non-string content type must be rejected");
    assert!(err.contains("content_types[1]"), "got: {}", err);
}

#[test]
fn test_invalid_levels_rejected() {
    let gzip_err = CompressionPlugin::new(&json!({"gzip_level": 10}))
        .err()
        .expect("gzip levels above 9 must be rejected");
    assert!(gzip_err.contains("gzip_level"), "got: {}", gzip_err);

    let br_err = CompressionPlugin::new(&json!({"brotli_quality": 12}))
        .err()
        .expect("brotli qualities above 11 must be rejected");
    assert!(br_err.contains("brotli_quality"), "got: {}", br_err);
}

#[test]
fn test_gzip_level_boundary_values() {
    // 0, 1, and 9 are the inclusive boundary values accepted by the runtime.
    for level in [0u64, 1, 9] {
        let plugin = CompressionPlugin::new(&json!({"gzip_level": level}))
            .unwrap_or_else(|e| panic!("gzip_level {level} must be accepted: {e}"));
        assert!(plugin.requires_response_body_buffering());
    }

    // 10 is the first rejected value (just above the maximum of 9).
    let err = CompressionPlugin::new(&json!({"gzip_level": 10}))
        .err()
        .expect("gzip_level 10 must be rejected");
    assert!(err.contains("gzip_level"), "got: {}", err);
    assert!(err.contains("0 and 9"), "got: {}", err);
}

#[test]
fn test_unknown_algorithm_rejected() {
    let err = CompressionPlugin::new(&json!({"algorithms": ["lz4"]}))
        .err()
        .expect("unknown algorithm must be rejected");
    assert!(err.contains("unknown algorithm"), "got: {}", err);
}

#[test]
fn test_unknown_algorithm_in_mixed_array_rejected() {
    // A typo in one algorithm should fail the whole config (no silent skip).
    let err = CompressionPlugin::new(&json!({"algorithms": ["gzip", "deflate"]}))
        .err()
        .expect("typo'd algorithm must be rejected");
    assert!(err.contains("unknown algorithm"), "got: {}", err);
}

#[test]
fn test_non_string_algorithm_rejected() {
    let err = CompressionPlugin::new(&json!({"algorithms": [42]}))
        .err()
        .expect("non-string algorithm must be rejected");
    assert!(err.contains("must be a string"), "got: {}", err);
}

#[test]
fn test_non_array_algorithms_rejected() {
    let err = CompressionPlugin::new(&json!({"algorithms": "gzip"}))
        .err()
        .expect("non-array algorithms must be rejected");
    assert!(err.contains("must be an array"), "got: {}", err);
}

#[test]
fn test_brotli_alias_accepted() {
    let plugin = CompressionPlugin::new(&json!({"algorithms": ["brotli"]}))
        .expect("'brotli' is accepted as an alias for 'br'");
    assert!(plugin.requires_response_body_buffering());
}

#[test]
fn test_empty_algorithms_array_rejected() {
    let err = CompressionPlugin::new(&json!({"algorithms": []}))
        .err()
        .expect("empty algorithms array must be rejected");
    assert!(err.contains("no valid algorithms"), "got: {}", err);
}

// ────────────────────── Accept-Encoding negotiation ──────────────────────

#[tokio::test]
async fn test_selects_gzip_from_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert_eq!(resp_headers.get("vary").unwrap(), "Accept-Encoding");
    assert!(!resp_headers.contains_key("content-length")); // removed
}

#[tokio::test]
async fn test_selects_brotli_from_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/html".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_x_gzip_compatibility_token_selects_canonical_gzip() {
    let plugin = make_plugin(json!({"algorithms": ["gzip"]}));
    let mut ctx = make_ctx(Some("x-gzip"));
    let mut request_headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut request_headers).await;

    let mut response_headers = HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("content-length".to_string(), "1000".to_string()),
    ]);
    assert!(matches!(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        response_headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "legacy x-gzip negotiation must emit the canonical gzip coding"
    );
}

#[tokio::test]
async fn test_prefers_higher_quality_algorithm() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip;q=0.5, br;q=1.0"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_server_preference_breaks_ties() {
    // gzip is first in default config, so it wins on tie
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");

    // Now with brotli first in config
    let plugin = make_plugin(json!({"algorithms": ["br", "gzip"]}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_wildcard_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("*"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    // Should pick first configured algorithm (gzip by default)
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_q_zero_rejects_algorithm() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip;q=0, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

// ────────────────────── Identity negotiation (RFC 9110 §12.5.3) ──────────────────────

#[tokio::test]
async fn test_higher_identity_quality_sends_uncoded_response() {
    // identity;q=1 beats gzip;q=0.2: the uncoded representation is the most
    // preferred acceptable one, so the gateway must not compress.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("identity;q=1, gzip;q=0.2"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(
        resp_headers.get("vary").map(String::as_str),
        Some("Accept-Encoding"),
        "eligible identity variants must nominate Vary for shared caches"
    );
}

#[tokio::test]
async fn test_identity_tie_keeps_server_compression_preference() {
    // gzip and identity tied at q=1: server preference order keeps the
    // existing behavior of compressing.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip, identity;q=1"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_identity_refusal_with_acceptable_algorithm_still_compresses() {
    // identity;q=0 excludes the uncoded representation, but gzip;q=0.5 is
    // acceptable and is the only acceptable representation Ferrum can produce.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("identity;q=0, gzip;q=0.5"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_refused_algorithms_without_identity_exclusion_send_identity() {
    // gzip/br refused but identity not excluded: identity is acceptable by
    // default (RFC 9110 §12.5.3), so the response is sent uncoded.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip;q=0, br;q=0"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_wildcard_refusal_with_identity_override_sends_identity() {
    // `*;q=0` refuses every coding including identity, but the more-specific
    // identity entry overrides the wildcard (RFC 9110 §12.5.3).
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("*;q=0, identity;q=1"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_wildcard_quality_applies_to_unlisted_algorithms_not_identity() {
    // `*;q=0.3` assigns q=0.3 to unlisted gzip/br only. Identity stays at its
    // default q=1 unless explicitly refused (RFC 9110 §12.5.3), so with
    // `identity;q=0` the wildcard algorithm is the only acceptable
    // representation and the gateway compresses.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("identity;q=0, *;q=0.3"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_identity_wildcard_quality_semantics_table() {
    // Distinguishes RFC 9110 §12.5.3 identity/wildcard semantics:
    // nonzero wildcard must not lower default identity q=1; explicit identity
    // overrides `*;q=0`; bare `*;q=0` refuses identity.
    #[derive(Debug)]
    enum Expect {
        Identity,
        Compress(&'static str),
        NotAcceptable,
    }
    let cases = [
        ("*;q=0.3", Expect::Identity),
        ("gzip;q=0.2, *;q=0.3", Expect::Identity),
        ("identity;q=0.8, *;q=0.3", Expect::Identity),
        ("identity;q=0.2, gzip;q=0.8", Expect::Compress("gzip")),
        ("*;q=0, identity;q=1", Expect::Identity),
        ("identity;q=1, *;q=0", Expect::Identity),
        ("*;q=0", Expect::NotAcceptable),
        // First identity entry wins (parity with response_representation).
        ("identity;q=0, identity;q=1", Expect::NotAcceptable),
        ("identity;q=1, identity;q=0", Expect::Identity),
    ];

    for (accept_encoding, expect) in cases {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some(accept_encoding));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());

        let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        match expect {
            Expect::Identity => {
                assert!(
                    matches!(result, PluginResult::Continue),
                    "{accept_encoding}: expected identity continue, got {result:?}"
                );
                assert!(
                    !resp_headers.contains_key("content-encoding"),
                    "{accept_encoding}: identity must not set content-encoding"
                );
            }
            Expect::Compress(encoding) => {
                assert!(
                    matches!(result, PluginResult::Continue),
                    "{accept_encoding}: expected compress continue, got {result:?}"
                );
                assert_eq!(
                    resp_headers.get("content-encoding").map(String::as_str),
                    Some(encoding),
                    "{accept_encoding}"
                );
            }
            Expect::NotAcceptable => match result {
                PluginResult::Reject {
                    status_code,
                    headers,
                    ..
                } => {
                    assert_eq!(status_code, 406, "{accept_encoding}");
                    assert!(!headers.contains_key("content-encoding"));
                    assert!(!resp_headers.contains_key("content-encoding"));
                }
                other => panic!("{accept_encoding}: expected 406, got {other:?}"),
            },
        }
    }
}

#[tokio::test]
async fn test_no_acceptable_representation_returns_406() {
    // Every representation Ferrum can produce has quality zero: identity and
    // all configured algorithms are refused. The negotiation must fail with
    // 406 instead of sending an explicitly excluded identity representation,
    // and no compression fields may be committed (RFC 9110 §12.5.3).
    for accept_encoding in [
        "gzip;q=0, br;q=0, identity;q=0",
        "zstd, identity;q=0",
        "*;q=0",
    ] {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some(accept_encoding));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());

        let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        match result {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(status_code, 406, "Accept-Encoding: {accept_encoding}");
                assert!(body.contains("not acceptable"));
                assert!(!headers.contains_key("content-encoding"));
                assert_eq!(
                    headers.get("vary").map(String::as_str),
                    Some("Accept-Encoding")
                );
            }
            other => panic!("expected 406 for {accept_encoding:?}, got {other:?}"),
        }
        // No compression fields were committed to the backend response.
        assert!(!resp_headers.contains_key("content-encoding"));
    }
}

#[tokio::test]
async fn test_malformed_identity_qvalue_is_not_a_refusal() {
    // A malformed identity qvalue cannot express a refusal: only a
    // well-formed RFC 9110 §12.4.2 `q=0` weight forbids identity. Unparseable
    // input leaves identity acceptable, so the request is served uncoded
    // instead of producing a 406 (parity with the shared
    // `identity_coding_is_acceptable` predicate in `response_representation`).
    for accept_encoding in [
        "gzip;q=0, br;q=0, identity;q=bogus",
        // Four fraction digits fall outside the qvalue grammar.
        "gzip;q=0, br;q=0, identity;q=0.0000",
        "zstd, *;q=bogus",
    ] {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some(accept_encoding));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());

        let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "malformed identity qvalue must not produce a 406: {accept_encoding}"
        );
        assert!(!resp_headers.contains_key("content-encoding"));
    }
}

#[tokio::test]
async fn test_406_fail_closed_when_ineligible_and_identity_unacceptable() {
    // Once compression owns Accept-Encoding negotiation, a response that
    // cannot be encoded (content-type / min size) must still 406 when identity
    // is unacceptable — never forward the excluded identity body, and never
    // partially mutate compression headers on the reject path.
    for (accept_encoding, mut resp_headers) in [
        ("*;q=0", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "image/png".to_string());
            h.insert("content-length".to_string(), "1000".to_string());
            h
        }),
        ("gzip;q=1, identity;q=0", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "application/json".to_string());
            // Below default min_content_length (256).
            h.insert("content-length".to_string(), "100".to_string());
            h
        }),
        ("identity;q=0, *;q=0.3", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "image/png".to_string());
            h.insert("content-length".to_string(), "5000".to_string());
            h
        }),
    ] {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some(accept_encoding));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let original = resp_headers.clone();
        let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        match result {
            PluginResult::Reject {
                status_code,
                body,
                headers: reject_headers,
            } => {
                assert_eq!(status_code, 406, "{accept_encoding}");
                assert!(body.contains("not acceptable"));
                assert!(!reject_headers.contains_key("content-encoding"));
                assert_eq!(
                    reject_headers.get("vary").map(String::as_str),
                    Some("Accept-Encoding")
                );
            }
            other => panic!("expected 406 for {accept_encoding:?}, got {other:?}"),
        }
        // Backend response map must be untouched (no partial compression mutation).
        assert_eq!(resp_headers, original, "{accept_encoding}");
        assert!(!ctx.metadata.contains_key("compression:algorithm"));
    }
}

#[tokio::test]
async fn test_406_not_applied_to_nobody_or_already_encoded_responses() {
    // Protocol-correct hard skips: no representation payload, or upstream
    // already selected a coding. Do not invent a 406 for these.
    for (status, accept_encoding, mut resp_headers) in [
        (204, "*;q=0", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "application/json".to_string());
            h
        }),
        (304, "identity;q=0", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "application/json".to_string());
            h
        }),
        (200, "*;q=0", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "application/json".to_string());
            h.insert("content-length".to_string(), "1000".to_string());
            h.insert("content-encoding".to_string(), "gzip".to_string());
            h
        }),
        // Already-coded range/delta remains a true protocol hard skip.
        (206, "identity;q=0", {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "application/json".to_string());
            h.insert("content-length".to_string(), "100".to_string());
            h.insert("content-range".to_string(), "bytes 0-99/5000".to_string());
            h.insert("content-encoding".to_string(), "gzip".to_string());
            h
        }),
    ] {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some(accept_encoding));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let result = plugin
            .after_proxy(&mut ctx, status, &mut resp_headers)
            .await;
        assert!(
            matches!(result, PluginResult::Continue),
            "status={status} ae={accept_encoding}: expected Continue, got {result:?}"
        );
    }
}

#[tokio::test]
async fn test_empty_accept_encoding_value_sends_identity() {
    // An empty field value makes only the identity coding acceptable
    // (RFC 9110 §12.5.3); the response is forwarded uncoded.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some(""));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_406_via_shared_after_proxy_chokepoint() {
    // H1/H2, native H3, and H3 cross-protocol all invoke
    // `proxy::run_after_proxy_hooks` for response negotiation. Prove that
    // chokepoint selects compression and returns 406 with no Content-Encoding.
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(make_plugin(json!({})))];
    let mut ctx = make_ctx(Some("*;q=0"));
    let mut req_headers = HashMap::new();
    plugins[0].before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let (status, _body, headers) =
        run_after_proxy_hooks_reject_for_test(&plugins, &mut ctx, 200, &mut resp_headers)
            .await
            .expect("shared after_proxy chokepoint must produce 406");
    assert_eq!(status, 406);
    assert!(
        headers
            .get("vary")
            .is_some_and(|vary| vary.eq_ignore_ascii_case("Accept-Encoding")),
        "cached Vary field-name tokens are case-insensitive"
    );
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert!(
        !headers.contains_key("content-encoding"),
        "406 path must not commit content-encoding"
    );
}

#[test]
fn test_h1_h2_h3_paths_reach_shared_after_proxy_chokepoint() {
    // Behavioral coverage above exercises `run_after_proxy_hooks`. Pin that
    // each real protocol surface reaches that helper rather than only flipping
    // an HTTP Version on a Response builder.
    let h1_h2 = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/server.rs");
    let h3_cross = include_str!("../../../src/http3/cross_protocol.rs");

    assert!(
        h1_h2.contains("let after_proxy_reject = run_after_proxy_hooks(")
            && h1_h2.contains("&mut plugin_response_headers,"),
        "H1/H2 buffered path must call run_after_proxy_hooks"
    );
    assert!(
        h1_h2.contains(
            "run_after_proxy_hooks(&plugins, &mut ctx, response_status, &mut response_headers).await"
        ),
        "H1/H2 streaming path must call run_after_proxy_hooks"
    );
    // Main may wrap the reject in `let mut` for synthetic-body prep; pin the
    // helper body itself (not a distant call site) still delegates to the
    // shared chokepoint with the streaming-wrapper argument shape.
    const H3_STREAMING_HELPER: &str = "async fn run_h3_streaming_after_proxy_hooks(";
    const H3_STREAMING_DELEGATION: &str =
        "run_after_proxy_hooks(plugins, ctx, response_status, response_headers).await";
    let h3_helper = h3
        .find(H3_STREAMING_HELPER)
        .map(|start| &h3[start..h3.len().min(start.saturating_add(1200))])
        .unwrap_or("");
    assert!(
        !h3_helper.is_empty() && h3_helper.contains(H3_STREAMING_DELEGATION),
        "native H3 streaming path must delegate to run_after_proxy_hooks"
    );
    assert!(
        h3.contains(
            "run_after_proxy_hooks(&plugins, &mut ctx, response_status, &mut response_headers)"
        ),
        "native H3 buffered path must call run_after_proxy_hooks"
    );
    assert!(
        h3_cross.contains("crate::proxy::run_after_proxy_hooks("),
        "H3 cross-protocol path must call run_after_proxy_hooks"
    );
}

#[tokio::test]
async fn test_shared_cache_identity_first_then_gzip_brotli_variants() {
    let _policy_guard = response_cache_replay_policy_guard();
    // #2355 acceptance: populate the built-in shared cache with an eligible
    // identity/default variant first, then prove later gzip / Brotli /
    // identity;q=0 requests miss that entry instead of replaying identity.
    // H1/H2/H3 all reach the same after_proxy chokepoint exercised here
    // (see test_h1_h2_h3_paths_reach_shared_after_proxy_chokepoint).
    let cache =
        Arc::new(ResponseCaching::new(&json!({"ttl_seconds": 60})).unwrap()) as Arc<dyn Plugin>;
    let compression = Arc::new(make_plugin(json!({}))) as Arc<dyn Plugin>;
    let identity_body = br#"{"cached":"identity-default"}"#;

    // Miss path: no Accept-Encoding → identity representation + Vary nomination.
    let mut store_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cache-vary-order".to_string(),
    );
    store_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    prove_empty_request_body(&mut store_ctx);
    seed_response_cache_presentation_policy(&mut store_ctx);
    let mut store_req = HashMap::new();
    assert!(matches!(
        cache.before_proxy(&mut store_ctx, &mut store_req).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        compression
            .before_proxy(&mut store_ctx, &mut store_req)
            .await,
        PluginResult::Continue
    ));

    let mut store_resp = HashMap::new();
    store_resp.insert("content-type".to_string(), "application/json".to_string());
    store_resp.insert("content-length".to_string(), "1000".to_string());
    store_resp.insert("cache-control".to_string(), "max-age=60".to_string());
    cache
        .after_proxy(&mut store_ctx, 200, &mut store_resp)
        .await;
    assert!(matches!(
        compression
            .after_proxy(&mut store_ctx, 200, &mut store_resp)
            .await,
        PluginResult::Continue
    ));
    assert!(
        !store_resp.contains_key("content-encoding"),
        "default/identity store must remain uncoded"
    );
    assert_eq!(
        store_resp.get("vary").map(String::as_str),
        Some("Accept-Encoding"),
        "identity-first store must nominate Vary before response_caching inserts"
    );
    cache
        .on_final_response_body(&mut store_ctx, 200, &store_resp, identity_body)
        .await;

    // Same absent Accept-Encoding → HIT of the identity variant.
    let mut hit_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cache-vary-order".to_string(),
    );
    hit_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    prove_empty_request_body(&mut hit_ctx);
    seed_response_cache_presentation_policy(&mut hit_ctx);
    let mut hit_headers = HashMap::new();
    let (status, body, headers) = match cache.before_proxy(&mut hit_ctx, &mut hit_headers).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body.into_bytes(), headers),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => (status_code, body.to_vec(), headers),
        other => panic!("expected identity HIT, got {other:?}"),
    };
    assert_eq!(status, 200);
    assert_eq!(body, identity_body);
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT")
    );
    assert!(
        headers.get("vary").is_some_and(|vary| {
            vary.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("Accept-Encoding"))
        }),
        "cached Vary field-name tokens are case-insensitive"
    );

    // Later gzip / br / identity;q=0 requests must miss the identity entry.
    for accept_encoding in ["gzip", "br", "gzip, identity;q=0", "identity;q=0, br"] {
        let mut miss_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cache-vary-order".to_string(),
        );
        miss_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
        prove_empty_request_body(&mut miss_ctx);
        seed_response_cache_presentation_policy(&mut miss_ctx);
        miss_ctx
            .headers
            .insert("accept-encoding".to_string(), accept_encoding.to_string());
        let mut miss_headers = miss_ctx.headers.clone();
        let result = cache.before_proxy(&mut miss_ctx, &mut miss_headers).await;
        assert!(
            matches!(result, PluginResult::Continue),
            "Accept-Encoding={accept_encoding}: must miss identity-first cache entry, got {result:?}"
        );
    }

    // Store a gzip variant through the same plugin order, then prove it hits
    // only for gzip and still misses for br / absent Accept-Encoding.
    let mut gzip_store_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cache-vary-order".to_string(),
    );
    gzip_store_ctx.max_response_body_size_bytes = 10 * 1024 * 1024;
    gzip_store_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    prove_empty_request_body(&mut gzip_store_ctx);
    seed_response_cache_presentation_policy(&mut gzip_store_ctx);
    gzip_store_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_store_req = gzip_store_ctx.headers.clone();
    assert!(matches!(
        cache
            .before_proxy(&mut gzip_store_ctx, &mut gzip_store_req)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        compression
            .before_proxy(&mut gzip_store_ctx, &mut gzip_store_req)
            .await,
        PluginResult::Continue
    ));
    let mut gzip_resp = HashMap::new();
    gzip_resp.insert("content-type".to_string(), "application/json".to_string());
    gzip_resp.insert("content-length".to_string(), "1000".to_string());
    gzip_resp.insert("cache-control".to_string(), "max-age=60".to_string());
    cache
        .after_proxy(&mut gzip_store_ctx, 200, &mut gzip_resp)
        .await;
    assert!(matches!(
        compression
            .after_proxy(&mut gzip_store_ctx, 200, &mut gzip_resp)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        gzip_resp.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_eq!(
        gzip_resp.get("vary").map(String::as_str),
        Some("Accept-Encoding")
    );
    // Body bytes after transform_response_body would be compressed; the cache
    // stores whatever final body the gateway supplies. Use distinct bytes so
    // the HIT assertion cannot confuse identity and gzip variants.
    let gzip_body = b"gzip-variant-bytes";
    cache
        .on_final_response_body(&mut gzip_store_ctx, 200, &gzip_resp, gzip_body)
        .await;

    let mut gzip_hit_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cache-vary-order".to_string(),
    );
    gzip_hit_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    prove_empty_request_body(&mut gzip_hit_ctx);
    seed_response_cache_presentation_policy(&mut gzip_hit_ctx);
    gzip_hit_ctx
        .headers
        .insert("accept-encoding".to_string(), "gzip".to_string());
    let mut gzip_hit_headers = gzip_hit_ctx.headers.clone();
    let (status, body, headers) = match cache
        .before_proxy(&mut gzip_hit_ctx, &mut gzip_hit_headers)
        .await
    {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body.into_bytes(), headers),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => (status_code, body.to_vec(), headers),
        other => panic!("expected gzip HIT, got {other:?}"),
    };
    assert_eq!(status, 200);
    assert_eq!(body, gzip_body);
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_eq!(
        headers.get("x-cache-status").map(String::as_str),
        Some("HIT")
    );

    for accept_encoding in [None, Some("br"), Some("identity;q=0, br")] {
        let mut miss_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cache-vary-order".to_string(),
        );
        miss_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
        prove_empty_request_body(&mut miss_ctx);
        seed_response_cache_presentation_policy(&mut miss_ctx);
        if let Some(ae) = accept_encoding {
            miss_ctx
                .headers
                .insert("accept-encoding".to_string(), ae.to_string());
        }
        let mut miss_headers = miss_ctx.headers.clone();
        // Absent Accept-Encoding still matches the identity-first entry.
        let result = cache.before_proxy(&mut miss_ctx, &mut miss_headers).await;
        if accept_encoding.is_none() {
            let body = match result {
                PluginResult::Reject { body, .. } => body.into_bytes(),
                PluginResult::RejectBinary { body, .. } => body.to_vec(),
                other => panic!("expected identity HIT for absent AE, got {other:?}"),
            };
            assert_eq!(
                body, identity_body,
                "absent Accept-Encoding must keep hitting the identity variant"
            );
        } else {
            assert!(
                matches!(result, PluginResult::Continue),
                "Accept-Encoding={accept_encoding:?}: must miss gzip variant, got {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_response_cache_hit_cannot_bypass_required_406() {
    let _policy_guard = response_cache_replay_policy_guard();
    // Compose response_caching + compression. An identity variant cached
    // without Vary: Accept-Encoding (#2355) must still be replaced by 406 when
    // a later request refuses identity — the shared reject-path after_proxy
    // negotiation must not be skipped on cache HIT.
    let cache =
        Arc::new(ResponseCaching::new(&json!({"ttl_seconds": 60})).unwrap()) as Arc<dyn Plugin>;
    let compression = Arc::new(make_plugin(json!({}))) as Arc<dyn Plugin>;
    let plugins = vec![cache, compression];

    // Miss path: store an identity body with no Vary (the #2355 shape).
    let mut store_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cache-406".to_string(),
    );
    store_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    prove_empty_request_body(&mut store_ctx);
    seed_response_cache_presentation_policy(&mut store_ctx);
    // Seed the defensive replay case under the same origin-visible request
    // partition as the later HIT. A different Accept-Encoding now correctly
    // selects a different base key.
    store_ctx
        .headers
        .insert("accept-encoding".to_string(), "*;q=0".to_string());
    let mut store_headers = store_ctx.headers.clone();
    assert!(matches!(
        plugins[0]
            .before_proxy(&mut store_ctx, &mut store_headers)
            .await,
        PluginResult::Continue
    ));
    let mut store_resp = HashMap::new();
    store_resp.insert("content-type".to_string(), "application/json".to_string());
    store_resp.insert("cache-control".to_string(), "max-age=60".to_string());
    // Deliberately omit Vary: Accept-Encoding (identity-variant gap in #2355).
    plugins[0]
        .after_proxy(&mut store_ctx, 200, &mut store_resp)
        .await;
    plugins[0]
        .on_final_response_body(
            &mut store_ctx,
            200,
            &store_resp,
            br#"{"cached":"identity"}"#,
        )
        .await;

    // Hit path: client refuses identity. Cache serves the identity body via
    // before_proxy Reject and short-circuits later before_proxy hooks
    // (compression never snapshots Accept-Encoding). Reject-path finalization
    // must still negotiate from ctx.headers and replace the HIT with 406.
    let mut hit_ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/cache-406".to_string(),
    );
    hit_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    prove_empty_request_body(&mut hit_ctx);
    seed_response_cache_presentation_policy(&mut hit_ctx);
    hit_ctx
        .headers
        .insert("accept-encoding".to_string(), "*;q=0".to_string());
    let mut hit_headers = hit_ctx.headers.clone();

    let (status, body, resp_headers) = match plugins[0]
        .before_proxy(&mut hit_ctx, &mut hit_headers)
        .await
    {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body.into_bytes(), headers),
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => (status_code, body.to_vec(), headers),
        other => panic!("expected cache HIT reject, got {other:?}"),
    };
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"cached":"identity"}"#);

    let (final_status, final_body, final_headers) = finalize_plugin_rejection_parts_for_test(
        &plugins,
        &mut hit_ctx,
        status,
        body,
        resp_headers,
    )
    .await;

    assert_eq!(final_status, 406, "cache HIT must not bypass required 406");
    assert!(
        String::from_utf8_lossy(&final_body).contains("not acceptable"),
        "406 body should replace the cached identity payload"
    );
    assert!(
        !final_headers.contains_key("content-encoding"),
        "406 path must not commit content-encoding"
    );
    assert_eq!(
        final_headers.get("vary").map(String::as_str),
        Some("Accept-Encoding")
    );
}

#[tokio::test]
async fn test_response_cache_hit_preserves_identity_when_acceptable() {
    let _policy_guard = response_cache_replay_policy_guard();
    // Cache HIT + absent / identity-acceptable Accept-Encoding must keep the
    // cached identity representation — replacement is only when identity is
    // explicitly unacceptable.
    let cache =
        Arc::new(ResponseCaching::new(&json!({"ttl_seconds": 60})).unwrap()) as Arc<dyn Plugin>;
    let compression = Arc::new(make_plugin(json!({}))) as Arc<dyn Plugin>;
    let plugins = vec![cache, compression];

    for accept_encoding in [None, Some("gzip"), Some("identity")] {
        // Every backend-visible request header is part of the response-cache
        // base partition. Seed each Accept-Encoding case under the exact
        // request view that will perform the HIT.
        let mut store_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cache-identity-ok".to_string(),
        );
        store_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
        prove_empty_request_body(&mut store_ctx);
        seed_response_cache_presentation_policy(&mut store_ctx);
        if let Some(ae) = accept_encoding {
            store_ctx
                .headers
                .insert("accept-encoding".to_string(), ae.to_string());
        }
        let mut store_headers = store_ctx.headers.clone();
        assert!(matches!(
            plugins[0]
                .before_proxy(&mut store_ctx, &mut store_headers)
                .await,
            PluginResult::Continue
        ));
        let mut store_resp = HashMap::new();
        store_resp.insert("content-type".to_string(), "application/json".to_string());
        store_resp.insert("cache-control".to_string(), "max-age=60".to_string());
        plugins[0]
            .after_proxy(&mut store_ctx, 200, &mut store_resp)
            .await;
        plugins[0]
            .on_final_response_body(
                &mut store_ctx,
                200,
                &store_resp,
                br#"{"cached":"identity"}"#,
            )
            .await;

        let mut hit_ctx = RequestContext::new(
            "127.0.0.1".to_string(),
            "GET".to_string(),
            "/cache-identity-ok".to_string(),
        );
        hit_ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
        prove_empty_request_body(&mut hit_ctx);
        seed_response_cache_presentation_policy(&mut hit_ctx);
        if let Some(ae) = accept_encoding {
            hit_ctx
                .headers
                .insert("accept-encoding".to_string(), ae.to_string());
        }
        let mut hit_headers = hit_ctx.headers.clone();

        let (status, body, resp_headers) = match plugins[0]
            .before_proxy(&mut hit_ctx, &mut hit_headers)
            .await
        {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => (status_code, body.into_bytes(), headers),
            PluginResult::RejectBinary {
                status_code,
                body,
                headers,
            } => (status_code, body.to_vec(), headers),
            other => panic!("expected cache HIT reject, got {other:?}"),
        };
        assert_eq!(status, 200);
        assert!(ferrum_edge::_test_support::response_cache_hit_for_test(
            &hit_ctx
        ));

        let (final_status, final_body, final_headers) = finalize_plugin_rejection_parts_for_test(
            &plugins,
            &mut hit_ctx,
            status,
            body,
            resp_headers,
        )
        .await;

        assert_eq!(
            final_status, 200,
            "ae={accept_encoding:?}: acceptable identity must keep cache HIT"
        );
        assert_eq!(&final_body[..], br#"{"cached":"identity"}"#);
        assert!(
            !final_headers.contains_key("content-encoding"),
            "ae={accept_encoding:?}: must not commit content-encoding on reject path"
        );
    }
}

#[tokio::test]
async fn test_security_rejection_not_replaced_by_406() {
    // `may_replace_rejection_response` is global opt-in, but compression must
    // not mask unrelated auth/policy statuses when identity is unacceptable.
    struct AuthRejectPlugin;
    #[async_trait::async_trait]
    impl Plugin for AuthRejectPlugin {
        fn name(&self) -> &str {
            "test_auth_reject"
        }
        fn priority(&self) -> u16 {
            1000
        }
        async fn before_proxy(
            &self,
            _ctx: &mut RequestContext,
            _headers: &mut HashMap<String, String>,
        ) -> PluginResult {
            PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"unauthorized"}"#.to_string(),
                headers: HashMap::from([("www-authenticate".to_string(), "Bearer".to_string())]),
            }
        }
    }

    let plugins: Vec<Arc<dyn Plugin>> =
        vec![Arc::new(AuthRejectPlugin), Arc::new(make_plugin(json!({})))];
    let mut ctx = make_ctx(Some("*;q=0"));
    let mut headers = ctx.headers.clone();
    let (status, body, resp_headers) = match plugins[0].before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => (status_code, body.into_bytes(), headers),
        other => panic!("expected auth reject, got {other:?}"),
    };
    assert_eq!(status, 401);
    // No request-global hit marker — this is not a response_caching HIT.
    assert!(!ferrum_edge::_test_support::response_cache_hit_for_test(
        &ctx
    ));

    let (final_status, final_body, final_headers) =
        finalize_plugin_rejection_parts_for_test(&plugins, &mut ctx, status, body, resp_headers)
            .await;

    assert_eq!(
        final_status, 401,
        "auth rejection must not be masked by compression 406"
    );
    assert_eq!(&final_body[..], br#"{"error":"unauthorized"}"#);
    assert_eq!(
        final_headers.get("www-authenticate").map(String::as_str),
        Some("Bearer")
    );
    assert!(!final_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_identity_range_delta_continues_when_identity_acceptable() {
    // Identity range/delta responses are non-transformable: forward unchanged
    // when identity remains acceptable (including absent Accept-Encoding).
    let plugin = make_plugin(json!({}));
    for (status, accept_encoding, mut resp_headers) in [
        (206, Some("gzip"), {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "text/html".to_string());
            h.insert("content-length".to_string(), "100".to_string());
            h.insert("content-range".to_string(), "bytes 0-99/5000".to_string());
            h
        }),
        (226, Some("identity"), {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "text/html".to_string());
            h.insert("content-length".to_string(), "100".to_string());
            h.insert("im".to_string(), "vcdiff".to_string());
            h.insert("delta-base".to_string(), "\"version-1\"".to_string());
            h
        }),
        (200, None, {
            let mut h = HashMap::new();
            h.insert("content-type".to_string(), "text/html".to_string());
            h.insert("content-length".to_string(), "100".to_string());
            h.insert("content-range".to_string(), "bytes 0-99/5000".to_string());
            h
        }),
    ] {
        let mut ctx = make_ctx(accept_encoding);
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        let result = plugin
            .after_proxy(&mut ctx, status, &mut resp_headers)
            .await;
        assert!(
            matches!(result, PluginResult::Continue),
            "status={status} ae={accept_encoding:?}: expected Continue, got {result:?}"
        );
        assert!(!ctx.metadata.contains_key("compression:algorithm"));
        assert!(!resp_headers.contains_key("content-encoding"));
        assert_eq!(resp_headers.get("content-length").unwrap(), "100");
    }
}

#[tokio::test]
async fn test_identity_range_delta_406_when_identity_unacceptable() {
    // Identity range/delta cannot be safely re-encoded. When the client refuses
    // identity, fail closed with 406 instead of forwarding an excluded identity
    // representation (issue #2602).
    let plugin = make_plugin(json!({}));
    for (status, mut resp_headers, stamp_range_marker) in [
        (
            206,
            {
                let mut h = HashMap::new();
                h.insert("content-type".to_string(), "application/json".to_string());
                h.insert("content-length".to_string(), "1000".to_string());
                h.insert("content-range".to_string(), "bytes 0-999/5000".to_string());
                h
            },
            false,
        ),
        (
            226,
            {
                let mut h = HashMap::new();
                h.insert("content-type".to_string(), "application/json".to_string());
                h.insert("content-length".to_string(), "1000".to_string());
                h.insert("im".to_string(), "vcdiff".to_string());
                h.insert("delta-base".to_string(), "\"version-1\"".to_string());
                h
            },
            false,
        ),
        (
            200,
            {
                let mut h = HashMap::new();
                h.insert("content-type".to_string(), "application/json".to_string());
                h.insert("content-length".to_string(), "1000".to_string());
                h
            },
            true,
        ),
    ] {
        for accept_encoding in ["*;q=0", "identity;q=0", "identity;q=0, gzip;q=0, br;q=0"] {
            let mut ctx = make_ctx(Some(accept_encoding));
            if stamp_range_marker {
                ctx.metadata
                    .insert("ferrum:range_response".to_string(), "true".to_string());
            }
            let mut headers = HashMap::new();
            plugin.before_proxy(&mut ctx, &mut headers).await;

            match plugin
                .after_proxy(&mut ctx, status, &mut resp_headers)
                .await
            {
                PluginResult::Reject {
                    status_code,
                    headers: reject_headers,
                    ..
                } => {
                    assert_eq!(status_code, 406, "status={status} ae={accept_encoding}");
                    assert!(
                        !reject_headers.contains_key("content-encoding"),
                        "status={status} ae={accept_encoding}: 406 must not commit encoding"
                    );
                    assert_eq!(
                        reject_headers.get("vary").map(String::as_str),
                        Some("Accept-Encoding")
                    );
                }
                other => {
                    panic!("status={status} ae={accept_encoding}: expected 406, got {other:?}")
                }
            }
            assert!(
                !ctx.metadata.contains_key("compression:algorithm"),
                "must not commit algorithm metadata before 406"
            );
            assert!(
                !resp_headers.contains_key("content-encoding"),
                "must not mutate live response headers before 406"
            );
        }
    }
}

// ────────────────────── Skip conditions ──────────────────────

#[tokio::test]
async fn test_skips_204_no_content() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    plugin.after_proxy(&mut ctx, 204, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_skips_205_reset_content_absent_and_zero_content_length() {
    // Issue #2356: 205 must never be gateway-encoded. Preserve backend
    // Content-Length (absent or zero) and do not nominate Vary.
    let plugin = make_plugin(json!({"min_content_length": 1}));

    for content_length in [None, Some("0")] {
        let mut ctx = make_ctx(Some("gzip"));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        if let Some(cl) = content_length {
            resp_headers.insert("content-length".to_string(), cl.to_string());
        }

        assert!(matches!(
            plugin.after_proxy(&mut ctx, 205, &mut resp_headers).await,
            PluginResult::Continue
        ));
        assert!(
            !resp_headers.contains_key("content-encoding"),
            "205 must not commit Content-Encoding (cl={content_length:?})"
        );
        assert_eq!(
            resp_headers.get("content-length").map(String::as_str),
            content_length,
            "205 must preserve backend Content-Length (cl={content_length:?})"
        );
        assert!(
            !resp_headers.contains_key("vary"),
            "205 hard skip must not nominate Vary (cl={content_length:?})"
        );

        // Empty wire body must not be gzip/Brotli-encoded either.
        assert!(
            plugin
                .transform_response_body_with_context(
                    &mut ctx,
                    &[],
                    Some("application/json"),
                    &resp_headers,
                )
                .await
                .is_none()
        );
    }
}

#[tokio::test]
async fn test_skips_304_not_modified() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());

    plugin.after_proxy(&mut ctx, 304, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_skips_head_present_and_absent_content_length() {
    // Issue #2356: HEAD has no wire body the gateway can re-encode. Skip
    // gateway compression and preserve backend representation metadata
    // rather than inventing an encoded-empty Content-Length.
    let plugin = make_plugin(json!({"min_content_length": 256}));

    for content_length in [None, Some("1024")] {
        let mut ctx = make_ctx(Some("gzip"));
        ctx.method = "HEAD".to_string();
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        if let Some(cl) = content_length {
            resp_headers.insert("content-length".to_string(), cl.to_string());
        }

        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
            PluginResult::Continue
        ));
        assert!(
            !resp_headers.contains_key("content-encoding"),
            "HEAD must not commit Content-Encoding (cl={content_length:?})"
        );
        assert_eq!(
            resp_headers.get("content-length").map(String::as_str),
            content_length,
            "HEAD must preserve backend Content-Length (cl={content_length:?})"
        );
        assert!(
            !resp_headers.contains_key("vary"),
            "HEAD hard skip must not nominate Vary (cl={content_length:?})"
        );

        // No gateway compression was committed, so the empty HEAD wire body
        // must not be transformed into a compressed member.
        assert!(
            plugin
                .transform_response_body_with_context(
                    &mut ctx,
                    &[],
                    Some("application/json"),
                    &resp_headers,
                )
                .await
                .is_none(),
            "HEAD must never gzip an empty wire body (cl={content_length:?})"
        );
    }
}

#[tokio::test]
async fn test_skips_already_compressed() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-encoding".to_string(), "br".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    // Should keep existing content-encoding, not overwrite
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_skips_non_compressible_content_type() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "image/png".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_cache_control_no_transform_disables_compression() {
    let cases = [
        "no-transform",
        "public, max-age=60, no-transform",
        "public, No-TrAnSfOrM",
        " public ,   no-transform  ",
    ];

    for cache_control in cases {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some("gzip"));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());
        resp_headers.insert("cache-control".to_string(), cache_control.to_string());

        plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

        assert!(
            !ctx.metadata.contains_key("compression:algorithm"),
            "algorithm should not be selected for Cache-Control: {cache_control}"
        );
        assert!(
            !resp_headers.contains_key("content-encoding"),
            "Content-Encoding should not be set for Cache-Control: {cache_control}"
        );
        assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
        assert_eq!(resp_headers.get("cache-control").unwrap(), cache_control);
    }
}

#[tokio::test]
async fn test_mixed_case_cache_control_no_transform_disables_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("Cache-Control".to_string(), "no-transform".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
    assert_eq!(resp_headers.get("Cache-Control").unwrap(), "no-transform");
}

#[tokio::test]
async fn test_original_no_transform_marker_disables_compression_when_header_removed() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata.insert(
        "ferrum:no_transform_response".to_string(),
        "true".to_string(),
    );

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
}

#[tokio::test]
async fn test_cache_control_substring_no_transform_does_not_disable_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert(
        "cache-control".to_string(),
        "public, x-no-transform".to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert!(!resp_headers.contains_key("content-length"));
}

#[tokio::test]
async fn test_cache_control_quoted_no_transform_argument_does_not_disable_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert(
        "cache-control".to_string(),
        r#"private="set-cookie, no-transform, authorization""#.to_string(),
    );

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert!(!resp_headers.contains_key("content-length"));
}

#[tokio::test]
async fn test_request_cache_control_no_transform_disables_gateway_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    headers.insert("cache-control".to_string(), "no-transform".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(
        ctx.metadata
            .contains_key("compression:request_no_transform")
    );
    assert!(!ctx.metadata.contains_key("compression:accept_encoding"));
    assert_eq!(headers.get("accept-encoding").unwrap(), "gzip");

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &resp_headers
    ));

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
}

#[test]
fn test_response_buffering_is_narrowed_by_content_type() {
    let plugin = make_plugin(json!({}));
    let ctx = make_ctx(Some("gzip"));
    let headers = HashMap::new();

    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &headers
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; charset=utf-8"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("image/png"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/octet-stream"),
        200,
        &headers
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &headers));
}

#[test]
fn test_response_buffering_skips_cache_control_no_transform() {
    let plugin = make_plugin(json!({}));
    let ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert(
        "cache-control".to_string(),
        "public, no-transform".to_string(),
    );

    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));

    headers.insert(
        "cache-control".to_string(),
        "public, x-no-transform".to_string(),
    );
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));
}

#[test]
fn test_response_buffering_skips_no_transform_response_via_metadata_marker() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    ctx.metadata.insert(
        "ferrum:no_transform_response".to_string(),
        "true".to_string(),
    );

    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1000".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));
}

#[test]
fn test_response_buffering_skips_strong_etag() {
    let plugin = make_plugin(json!({}));
    let ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert("etag".to_string(), "\"abc123\"".to_string());

    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));

    headers.insert("etag".to_string(), "W/\"abc123\"".to_string());
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));

    headers.insert("etag".to_string(), "w/\"abc123\"".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));

    headers.insert("etag".to_string(), "W/ \"abc123\"".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));

    headers.insert("etag".to_string(), "W/\"old\", W/\"new\"".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));
}

#[test]
fn test_response_buffering_skips_strong_etag_via_metadata_marker() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    ctx.metadata.insert(
        "ferrum:strong_etag_response".to_string(),
        "true".to_string(),
    );

    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1000".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));
}

#[test]
fn test_response_buffering_skips_range_responses() {
    // A range response with a compressible content-type must not be pinned onto
    // the buffered path: `after_proxy` will skip compressing it, so buffering
    // would just delay/collect the body (and can trip the response body limit on
    // large ranged downloads) instead of streaming it. Mirrors the `after_proxy`
    // 206/Content-Range skip so the proxy can downgrade buffer -> stream.
    let plugin = make_plugin(json!({}));
    let ctx = make_ctx(Some("gzip"));

    // Preserved 206/226 representations (even without range/delta headers).
    let no_range = HashMap::new();
    for status in [206, 226] {
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/html"),
            status,
            &no_range
        ));
        assert!(
            plugin
                .should_release_response_body_before_content_type_rewrite(&ctx, status, &no_range)
        );
    }

    for status in [204, 205, 304] {
        assert!(!plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/html"),
            status,
            &no_range
        ));
        assert!(
            plugin
                .should_release_response_body_before_content_type_rewrite(&ctx, status, &no_range)
        );
    }

    // HEAD never buffers for compression (no wire body to re-encode).
    let mut head_ctx = make_ctx(Some("gzip"));
    head_ctx.method = "HEAD".to_string();
    assert!(!plugin.should_buffer_response_body(&head_ctx));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &head_ctx,
        Some("text/html"),
        200,
        &no_range
    ));
    assert!(
        plugin.should_release_response_body_before_content_type_rewrite(&head_ctx, 200, &no_range)
    );

    // A Content-Range header on a non-206 status also opts out.
    let mut range_headers = HashMap::new();
    range_headers.insert("content-range".to_string(), "bytes 0-99/5000".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &range_headers
    ));

    // A plain 200 with a compressible type still buffers (control).
    let plain = HashMap::new();
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &plain
    ));
}

#[test]
fn test_response_buffering_skips_range_responses_via_metadata_marker() {
    // On paths that run `after_proxy` before the refine/buffering decision (e.g.
    // the H3 cross-protocol path), `RANGE_RESPONSE_METADATA_KEY` is stamped from
    // the pristine backend headers. If an earlier-ordered hook (e.g.
    // `response_transformer`) then strips `Content-Range` and the status is not
    // 206, the live headers no longer reveal that this is a range response. The
    // buffering check must still opt out via the stamped marker so the partial
    // body streams instead of being pinned onto the buffered path (where it
    // would never be compressed and could trip the response body size limit) —
    // mirroring the `after_proxy` skip in
    // `test_skips_range_response_when_content_range_was_stripped`.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    ctx.metadata
        .insert("ferrum:range_response".to_string(), "true".to_string());

    // Live headers look like a plain compressible 200 (Content-Range stripped).
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-length".to_string(), "100".to_string());
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/html"),
        200,
        &resp_headers
    ));

    // Without the marker the same headers buffer (control), so the marker — not
    // some other signal — is what drives the opt-out.
    let ctx_no_marker = make_ctx(Some("gzip"));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx_no_marker,
        Some("text/html"),
        200,
        &resp_headers
    ));
}

#[test]
fn test_response_buffering_still_requires_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let ctx = make_ctx(None);
    let headers = HashMap::new();

    assert!(!plugin.should_buffer_response_body(&ctx));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json"),
        200,
        &headers
    ));
}

#[tokio::test]
async fn test_skips_preserved_representation_responses() {
    let plugin = make_plugin(json!({}));
    for status in [206, 226] {
        let mut ctx = make_ctx(Some("gzip"));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "text/html".to_string());
        resp_headers.insert("content-length".to_string(), "100".to_string());
        if status == 206 {
            resp_headers.insert("content-range".to_string(), "bytes 0-99/5000".to_string());
        } else {
            resp_headers.insert("im".to_string(), "vcdiff".to_string());
            resp_headers.insert("delta-base".to_string(), "\"version-1\"".to_string());
        }

        plugin
            .after_proxy(&mut ctx, status, &mut resp_headers)
            .await;

        assert!(!ctx.metadata.contains_key("compression:algorithm"));
        assert!(!resp_headers.contains_key("content-encoding"));
        assert_eq!(resp_headers.get("content-length").unwrap(), "100");
        if status == 206 {
            assert_eq!(
                resp_headers.get("content-range").unwrap(),
                "bytes 0-99/5000"
            );
        } else {
            assert_eq!(resp_headers.get("im").map(String::as_str), Some("vcdiff"));
            assert_eq!(
                resp_headers.get("delta-base").map(String::as_str),
                Some("\"version-1\"")
            );
        }
    }
}

#[tokio::test]
async fn test_skips_content_range_header_on_non_partial_status() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/html".to_string());
    resp_headers.insert("content-length".to_string(), "100".to_string());
    resp_headers.insert("content-range".to_string(), "bytes 0-99/5000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "100");
    assert_eq!(
        resp_headers.get("content-range").unwrap(),
        "bytes 0-99/5000"
    );
}

#[tokio::test]
async fn test_skips_range_response_when_content_range_was_stripped() {
    // Regression: an earlier-ordered plugin (e.g. `response_transformer` at 4000,
    // before `compression` at 4050) may strip `Content-Range` before
    // `compression.after_proxy` runs. Range responses are streamed, so committing
    // `Content-Encoding` here would mislabel an uncompressed body whose buffered-
    // only `transform_response_body` never runs. The proxy records the ORIGINAL
    // backend range decision under this marker before any after_proxy mutation, so
    // compression must still decline to compress even though the live headers no
    // longer carry `Content-Range` and the status was rewritten to 200.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // Simulate the proxy-side marker stamped from the pristine backend response.
    ctx.metadata
        .insert("ferrum:range_response".to_string(), "true".to_string());

    // Live headers after an earlier transform removed Content-Range and the
    // status is no longer 206.
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/html".to_string());
    resp_headers.insert("content-length".to_string(), "100".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(
        !resp_headers.contains_key("content-encoding"),
        "must not label a streamed range body as compressed"
    );
    assert_eq!(resp_headers.get("content-length").unwrap(), "100");
}

#[tokio::test]
async fn test_compresses_normal_response_without_range_marker() {
    // Control for the marker check: a plain 200 with no range marker and no
    // Content-Range still compresses, so the marker does not over-suppress.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/html".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert!(!resp_headers.contains_key("content-length"));
}

#[tokio::test]
async fn test_skips_below_min_content_length() {
    let plugin = make_plugin(json!({"min_content_length": 1000}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "500".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_strong_etag_disables_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "\"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
    assert_eq!(resp_headers.get("etag").unwrap(), "\"abc123\"");
}

#[tokio::test]
async fn test_mixed_case_strong_etag_disables_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("ETag".to_string(), "\"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
    assert_eq!(resp_headers.get("ETag").unwrap(), "\"abc123\"");
}

#[tokio::test]
async fn test_weak_etag_remains_eligible_for_compression() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "W/\"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert_eq!(resp_headers.get("etag").unwrap(), "W/\"abc123\"");
}

#[tokio::test]
async fn test_malformed_etag_is_preserved_like_strong_etag() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "not-a-valid-weak-etag".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
}

#[tokio::test]
async fn test_lowercase_weak_etag_prefix_is_preserved_like_malformed_etag() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "w/\"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
    assert_eq!(resp_headers.get("etag").unwrap(), "w/\"abc123\"");
}

#[tokio::test]
async fn test_whitespace_after_weak_etag_prefix_is_preserved_like_malformed_etag() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "W/ \"abc123\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
    assert_eq!(resp_headers.get("etag").unwrap(), "W/ \"abc123\"");
}

#[tokio::test]
async fn test_folded_duplicate_weak_etag_is_preserved_like_malformed_etag() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "W/\"old\", W/\"new\"".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
    assert_eq!(resp_headers.get("etag").unwrap(), "W/\"old\", W/\"new\"");
}

#[tokio::test]
async fn test_original_strong_etag_marker_disables_compression_when_header_removed() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    ctx.metadata.insert(
        "ferrum:strong_etag_response".to_string(),
        "true".to_string(),
    );

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;

    assert!(!ctx.metadata.contains_key("compression:algorithm"));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
}

#[tokio::test]
async fn test_skips_no_accept_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(
        resp_headers.get("vary").map(String::as_str),
        Some("Accept-Encoding"),
        "eligible default/identity responses must still nominate Vary"
    );
}

// ────────────────────── Vary header ──────────────────────

#[tokio::test]
async fn test_identity_default_nominates_vary_accept_encoding() {
    // #2355: eligible identity/default variants must nominate Accept-Encoding
    // even when no supported coding wins, so shared caches can distinguish them
    // from later gzip/Brotli selections.
    let plugin = make_plugin(json!({}));

    for accept_encoding in [None, Some("identity"), Some("identity;q=1, gzip;q=0.2")] {
        let mut ctx = make_ctx(accept_encoding);
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());
        resp_headers.insert("vary".to_string(), "Origin".to_string());

        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
            PluginResult::Continue
        ));
        assert!(
            !resp_headers.contains_key("content-encoding"),
            "ae={accept_encoding:?}: identity/default must stay uncoded"
        );
        assert_eq!(
            resp_headers.get("vary").map(String::as_str),
            Some("Origin, Accept-Encoding"),
            "ae={accept_encoding:?}: must append Accept-Encoding without dropping Origin"
        );
    }
}

#[tokio::test]
async fn test_identity_vary_preserves_wildcard_and_case_insensitive_dedupe() {
    let plugin = make_plugin(json!({}));

    // Vary: * already varies on every request header — leave it alone.
    let mut ctx = make_ctx(Some("identity"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "*".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("vary").map(String::as_str), Some("*"));

    // Case-insensitive de-dupe of an existing Accept-Encoding member.
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "accept-encoding, Origin".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(
        resp_headers.get("vary").map(String::as_str),
        Some("accept-encoding, Origin"),
        "must not duplicate Accept-Encoding case-insensitively"
    );

    // A present but empty upstream field must not produce a leading comma.
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "  ".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(
        resp_headers.get("vary").map(String::as_str),
        Some("Accept-Encoding")
    );
}

#[tokio::test]
async fn test_ineligible_identity_does_not_nominate_vary() {
    // Permanently ineligible shapes must not add Accept-Encoding as a cache
    // dimension — compression can never select a different representation.
    let plugin = make_plugin(json!({"min_content_length": 256}));

    // Non-whitelisted content type.
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "image/png".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("vary"));

    // Below min_content_length.
    let mut ctx = make_ctx(Some("identity"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "10".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("vary"));

    // No-body statuses (protocol hard skips), including 205.
    for status in [204u16, 205, 304] {
        let mut ctx = make_ctx(None);
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "application/json".to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());
        plugin
            .after_proxy(&mut ctx, status, &mut resp_headers)
            .await;
        assert!(
            !resp_headers.contains_key("vary"),
            "{status} hard skip must not nominate Vary"
        );
    }

    // HEAD is permanently ineligible for gateway coding.
    let mut ctx = make_ctx(Some("gzip"));
    ctx.method = "HEAD".to_string();
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("vary"));

    // Strong ETag forbids transform permanently for this representation.
    let mut ctx = make_ctx(Some("identity"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("etag".to_string(), "\"strong-validator\"".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("vary"));
}

#[tokio::test]
async fn test_vary_header_appended_to_existing() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "Origin".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("vary").unwrap(), "Origin, Accept-Encoding");
}

#[tokio::test]
async fn test_vary_header_not_duplicated() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "Accept-Encoding".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("vary").unwrap(), "Accept-Encoding");
}

#[tokio::test]
async fn test_vary_header_token_match_does_not_false_positive() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "X-Accept-Encoding-Mode".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(
        resp_headers.get("vary").unwrap(),
        "X-Accept-Encoding-Mode, Accept-Encoding"
    );
}

#[tokio::test]
async fn test_vary_header_wildcard_preserved_on_compressed_branch() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    resp_headers.insert("vary".to_string(), "*".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert_eq!(
        resp_headers.get("vary").map(String::as_str),
        Some("*"),
        "compressed branch must preserve Vary: *"
    );
}

#[tokio::test]
async fn test_rejection_after_proxy_marker_does_not_commit_encoding() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    ctx.metadata
        .insert("ferrum:rejection_response".to_string(), "true".to_string());
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 403, &mut resp_headers).await;

    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("content-length").unwrap(), "1000");
}

// ────────────────────── Remove Accept-Encoding ──────────────────────

#[tokio::test]
async fn test_removes_accept_encoding_from_backend_request() {
    let plugin = make_plugin(json!({"remove_accept_encoding": true}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(!headers.contains_key("accept-encoding"));
    // But the original is saved in metadata for after_proxy
    assert!(ctx.metadata.contains_key("compression:accept_encoding"));
}

#[tokio::test]
async fn test_preserves_accept_encoding_when_disabled() {
    let plugin = make_plugin(json!({"remove_accept_encoding": false}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(headers.contains_key("accept-encoding"));
}

// ────────────────────── Response compression (gzip) ──────────────────────

#[tokio::test]
async fn test_gzip_response_compression_roundtrip() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(None);

    // Use a repetitive body large enough that gzip overhead is worthwhile
    let original = r#"{"users":[{"name":"alice","email":"alice@example.com","role":"admin"},{"name":"bob","email":"bob@example.com","role":"user"},{"name":"charlie","email":"charlie@example.com","role":"user"},{"name":"dave","email":"dave@example.com","role":"moderator"},{"name":"eve","email":"eve@example.com","role":"user"},{"name":"frank","email":"frank@example.com","role":"admin"},{"name":"grace","email":"grace@example.com","role":"user"},{"name":"heidi","email":"heidi@example.com","role":"user"}]}"#.as_bytes();

    let mut resp_headers = HashMap::new();
    plan_response_algorithm(&plugin, &mut ctx, &mut resp_headers, "gzip").await;

    let compressed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            original,
            Some("application/json"),
            &resp_headers,
        )
        .await
        .expect("should compress");

    assert!(compressed.len() < original.len());

    // Verify it decompresses back to original
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, original);
}

// ────────────────────── Response compression (brotli) ──────────────────────

#[tokio::test]
async fn test_brotli_response_compression_roundtrip() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(None);

    let original = b"Hello, this is a test body that should be compressed with brotli encoding!";

    let mut resp_headers = HashMap::from([("content-type".to_string(), "text/html".to_string())]);
    plan_response_algorithm(&plugin, &mut ctx, &mut resp_headers, "br").await;

    let compressed = plugin
        .transform_response_body_with_context(&mut ctx, original, Some("text/html"), &resp_headers)
        .await
        .expect("should compress");

    assert!(compressed.len() < original.len());

    // Verify it decompresses back to original
    let mut decompressed = Vec::new();
    brotli::BrotliDecompress(&mut &compressed[..], &mut decompressed).unwrap();
    assert_eq!(decompressed, original);
}

// ────────────────────── Response: tiny body still compressed when committed ───
//
// Once `after_proxy` sets `Content-Encoding`, the response is committed to
// that encoding. Returning an uncompressed body with `Content-Encoding: gzip`
// would produce a malformed response that every conformant client rejects.
// `transform_response_body` therefore compresses unconditionally when the
// header has been set — the size gate runs in `after_proxy` for known-CL
// responses; tiny chunked bodies are accepted as a small cost for correctness.

#[tokio::test]
async fn test_compresses_tiny_body_when_committed_in_transform() {
    let plugin = make_plugin(json!({"min_content_length": 256}));
    let mut ctx = make_ctx(None);

    let tiny_body = b"small";

    let mut resp_headers = HashMap::new();
    plan_response_algorithm(&plugin, &mut ctx, &mut resp_headers, "gzip").await;

    let result = plugin
        .transform_response_body_with_context(
            &mut ctx,
            tiny_body,
            Some("application/json"),
            &resp_headers,
        )
        .await
        .expect("once Content-Encoding is set, transform must compress regardless of size");

    // Verify the body is actually gzip-compressed (not the original bytes)
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&result[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("output must be valid gzip");
    assert_eq!(decompressed, tiny_body);
}

#[tokio::test]
async fn test_transform_response_body_compresses_when_encoding_already_committed() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(None);

    let mut resp_headers = HashMap::new();
    plan_response_algorithm(&plugin, &mut ctx, &mut resp_headers, "gzip").await;
    resp_headers.insert("cache-control".to_string(), "no-transform".to_string());

    let original = b"compressible body";
    let compressed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            original,
            Some("application/json"),
            &resp_headers,
        )
        .await
        .expect("committed Content-Encoding must produce an encoded body");

    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
    assert_eq!(resp_headers.get("cache-control").unwrap(), "no-transform");

    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("output must be valid gzip");
    assert_eq!(decompressed, original);
}

#[tokio::test]
async fn test_transform_response_body_uses_final_supported_content_encoding() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(None);

    let mut resp_headers = HashMap::new();
    plan_response_algorithm(&plugin, &mut ctx, &mut resp_headers, "br").await;
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());

    let original = b"compressible body after final header rewrite";
    let compressed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            original,
            Some("application/json"),
            &resp_headers,
        )
        .await
        .expect("gateway-committed encoding should follow the final supported header");

    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("output must be valid gzip after final header rewrite");
    assert_eq!(decompressed, original);
}

#[tokio::test]
async fn test_transform_response_body_skips_origin_encoding_without_commit_metadata() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(None);

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());
    resp_headers.insert("cache-control".to_string(), "no-transform".to_string());

    let result = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"origin encoded body",
            Some("application/json"),
            &resp_headers,
        )
        .await;

    assert!(
        result.is_none(),
        "origin Content-Encoding must not trigger a second compression pass"
    );
}

#[tokio::test]
async fn test_after_proxy_skips_when_content_length_below_min() {
    // The size gate lives in `after_proxy` (when Content-Length is known).
    // When skipped there, no Content-Encoding is set, so transform stays inert.
    let plugin = make_plugin(json!({"min_content_length": 1000}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "100".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));

    // With no Content-Encoding committed, transform leaves the body alone.
    let result = plugin
        .transform_response_body_with_context(
            &mut ctx,
            b"small body",
            Some("application/json"),
            &resp_headers,
        )
        .await;
    assert!(result.is_none());
}

// ────────────────────── Request decompression (gzip) ──────────────────────

#[tokio::test]
async fn test_gzip_request_decompression() {
    let plugin = make_plugin(json!({"decompress_request": true}));

    let original = b"Hello, this is a gzip-compressed request body!";

    // Compress with gzip
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let decompressed = plugin
        .transform_request_body(&compressed, Some("application/json"), &headers)
        .await
        .expect("should decompress");

    assert_eq!(decompressed, original);
}

#[tokio::test]
async fn test_before_proxy_strips_client_supplied_internal_marker() {
    // A client must not be able to inject the gateway-internal marker
    // `x-ferrum-original-content-encoding` to coerce decompression attempts
    // on plaintext bodies.
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(None);
    let mut headers = HashMap::new();
    headers.insert(
        "x-ferrum-original-content-encoding".to_string(),
        "gzip".to_string(),
    );

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(
        !headers.contains_key("x-ferrum-original-content-encoding"),
        "client-supplied internal marker must be stripped"
    );
    assert!(
        !ctx.metadata.contains_key("compression:request_encoding"),
        "no real content-encoding was present; metadata must not be set"
    );

    // transform_request_body should NOT attempt decompression on a plaintext
    // body when only the client-supplied marker was present (now removed).
    let result = plugin
        .transform_request_body(b"plaintext body", Some("application/json"), &headers)
        .await;
    assert!(result.is_none());
}

// ────────────────────── Request decompression (brotli) ──────────────────────

#[tokio::test]
async fn test_brotli_request_decompression() {
    let plugin = make_plugin(json!({"decompress_request": true}));

    let original = b"Hello, this is a brotli-compressed request body!";

    // Compress with brotli
    let mut compressed = Vec::new();
    let params = brotli::enc::BrotliEncoderParams::default();
    brotli::BrotliCompress(&mut &original[..], &mut compressed, &params).unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "br".to_string());

    let decompressed = plugin
        .transform_request_body(&compressed, Some("application/json"), &headers)
        .await
        .expect("should decompress");

    assert_eq!(decompressed, original);
}

#[tokio::test]
async fn test_request_decompression_disabled_by_default() {
    let plugin = make_plugin(json!({})); // decompress_request defaults false

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let result = plugin
        .transform_request_body(b"some compressed data", Some("application/json"), &headers)
        .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_request_decompression_zip_bomb_protection() {
    let plugin = make_plugin(json!({
        "decompress_request": true,
        "max_decompressed_request_size": 100
    }));

    // Create a gzip payload that decompresses to > 100 bytes
    use flate2::write::GzEncoder;
    use std::io::Write;
    let big_body = vec![b'A'; 200];
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&big_body).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    // Should fail (return None) due to size limit
    let result = plugin
        .transform_request_body(&compressed, Some("application/json"), &headers)
        .await;
    assert!(result.is_none());
}

// ────────────────────── Content type matching ──────────────────────

#[tokio::test]
async fn test_content_type_with_charset() {
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_custom_content_types() {
    let plugin = make_plugin(json!({
        "content_types": ["application/vnd.api+json", "text/csv"]
    }));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // Standard JSON should NOT match custom whitelist
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));

    // Custom type should match
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "content-type".to_string(),
        "application/vnd.api+json".to_string(),
    );
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

/// #2329: early normalization replaces the buffered body with plaintext and
/// strips encoding headers only after successful decode.
#[tokio::test]
async fn test_normalize_buffered_request_body_decodes_before_before_proxy() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"early normalize plaintext";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());
    let mut body = compressed.clone();

    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body.as_slice(), original.as_slice());
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    assert_eq!(
        ctx.metadata
            .get("compression:request_decoded")
            .map(String::as_str),
        Some("gzip")
    );

    // before_proxy must not re-claim; transform must not decode again.
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(
        plugin
            .transform_request_body_with_context(&mut ctx, &body, None, &headers)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn test_buffered_normalizer_noop_preserves_existing_views_without_content_encoding() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(make_plugin(json!({
        "decompress_request": true
    })))];
    let mut ctx = make_ctx(None);
    ctx.metadata.insert(
        "request_body".to_string(),
        "preexisting body view".to_string(),
    );
    ctx.request_body_bytes = Some(bytes::Bytes::from_static(b"preexisting byte view"));
    let original_bytes_ptr = ctx.request_body_bytes.as_ref().unwrap().as_ptr();
    let mut headers = HashMap::new();
    let mut body = b"ordinary uncompressed request".to_vec();

    let result = apply_buffered_request_body_normalization_before_before_proxy_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
    )
    .await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body, b"ordinary uncompressed request");
    assert_eq!(
        ctx.metadata.get("request_body").map(String::as_str),
        Some("preexisting body view")
    );
    assert_eq!(
        ctx.request_body_bytes.as_ref().unwrap().as_ptr(),
        original_bytes_ptr,
        "a capability-only no-op must not copy an unchanged body view"
    );
}

#[tokio::test]
async fn test_binary_only_normalization_refreshes_bytes_without_materializing_text() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(make_plugin(json!({
        "decompress_request": true
    })))];
    let plaintext = b"binary consumer plaintext";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plaintext).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut ctx = make_ctx(None);
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(&compressed));
    ctx.request_body_sha256 = Some([0x25; 32]);
    ctx.request_body_sha512 = Some([0x51; 64]);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());
    let mut body = compressed;

    let result = apply_buffered_request_body_normalization_with_requirements_for_test(
        &plugins,
        &mut ctx,
        &mut headers,
        &mut body,
        false,
        true,
    )
    .await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body, plaintext);
    assert_eq!(
        ctx.request_body_bytes.as_deref(),
        Some(plaintext.as_slice())
    );
    assert!(!ctx.metadata.contains_key("request_body"));
    assert_eq!(ctx.request_body_sha256, Some([0x25; 32]));
    assert_eq!(ctx.request_body_sha512, Some([0x51; 64]));
}

// ────────────────────── before_proxy: request decompression header safety ─

#[tokio::test]
async fn test_before_proxy_preserves_encoded_headers_without_body_view() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), "42".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some("42")
    );
    assert!(!ctx.metadata.contains_key("compression:request_encoding"));
}

// ────────────────────── End-to-end: full lifecycle ──────────────────────

#[tokio::test]
async fn test_full_response_compression_lifecycle_gzip() {
    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(Some("gzip, br;q=0.8"));

    // before_proxy: save Accept-Encoding, strip from backend request
    let mut proxy_headers = HashMap::new();
    proxy_headers.insert("accept-encoding".to_string(), "gzip, br;q=0.8".to_string());
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert!(!proxy_headers.contains_key("accept-encoding"));

    // after_proxy: negotiate algorithm, set response headers
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "5000".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");

    // transform_response_body: compress
    let body = br#"{"users":[{"name":"alice","email":"alice@example.com","role":"admin"},{"name":"bob","email":"bob@example.com","role":"user"},{"name":"charlie","email":"charlie@example.com","role":"user"},{"name":"dave","email":"dave@example.com","role":"moderator"},{"name":"eve","email":"eve@example.com","role":"user"},{"name":"frank","email":"frank@example.com","role":"admin"},{"name":"grace","email":"grace@example.com","role":"user"},{"name":"heidi","email":"heidi@example.com","role":"user"}]}"#;
    let compressed = plugin
        .transform_response_body_with_context(
            &mut ctx,
            body,
            Some("application/json"),
            &resp_headers,
        )
        .await
        .expect("should compress");
    assert!(compressed.len() < body.len());

    // Verify roundtrip
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    assert_eq!(decompressed, body);
}

// ────────────────────── should_buffer_request_body ──────────────────────

#[test]
fn test_should_buffer_only_when_content_encoding_present() {
    let plugin = make_plugin(json!({"decompress_request": true}));

    let ctx_with_ce = {
        let mut ctx = make_ctx(None);
        ctx.headers
            .insert("content-encoding".to_string(), "gzip".to_string());
        ctx
    };
    assert!(plugin.should_buffer_request_body(&ctx_with_ce));

    let ctx_without_ce = make_ctx(None);
    assert!(!plugin.should_buffer_request_body(&ctx_without_ce));

    let ctx_no_transform = {
        let mut ctx = make_ctx(None);
        ctx.headers
            .insert("content-encoding".to_string(), "gzip".to_string());
        ctx.headers
            .insert("cache-control".to_string(), "no-transform".to_string());
        ctx
    };
    assert!(
        plugin.should_buffer_request_body(&ctx_no_transform),
        "request bodies still buffer so no-transform can preserve headers and body together"
    );
}

// ────────────────────── Algorithm-only config ──────────────────────

#[tokio::test]
async fn test_gzip_only_config() {
    let plugin = make_plugin(json!({"algorithms": ["gzip"]}));
    let mut ctx = make_ctx(Some("br, gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    // Should pick gzip since brotli isn't configured
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "gzip");
}

#[tokio::test]
async fn test_brotli_only_config() {
    let plugin = make_plugin(json!({"algorithms": ["br"]}));
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(resp_headers.get("content-encoding").unwrap(), "br");
}

#[tokio::test]
async fn test_no_matching_algorithm() {
    let plugin = make_plugin(json!({"algorithms": ["gzip"]}));
    let mut ctx = make_ctx(Some("br")); // client only wants brotli
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(!resp_headers.contains_key("content-encoding"));
}

// ──────────── Accept-Encoding specificity & malformed q (RFC 9110) ────────────

/// Drive the response-side algorithm negotiation for a given Accept-Encoding
/// and configured algorithm list, returning the selected `Content-Encoding`
/// (or `None` when no encoding was applied).
async fn negotiate_encoding(
    algorithms: serde_json::Value,
    accept_encoding: &str,
) -> Option<String> {
    let plugin = make_plugin(json!({ "algorithms": algorithms }));
    let mut ctx = make_ctx(Some(accept_encoding));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    resp_headers.get("content-encoding").cloned()
}

/// #58: an explicit `gzip;q=0` must exclude gzip even when a wildcard `*` is
/// present at q>0 — the more specific entry wins over `*` (RFC 9110 §12.5.3).
/// With brotli also configured, brotli is selected through the wildcard.
#[tokio::test]
async fn test_explicit_q_zero_not_reenabled_by_wildcard_selects_other() {
    let selected = negotiate_encoding(json!(["gzip", "br"]), "gzip;q=0, *").await;
    assert_eq!(
        selected.as_deref(),
        Some("br"),
        "explicit gzip;q=0 must not be re-enabled by the wildcard; brotli should win"
    );
}

/// #58: an explicit `gzip;q=0` with a wildcard, when gzip is the ONLY configured
/// algorithm, must apply no encoding — the wildcard cannot resurrect the
/// specifically-refused codec.
#[tokio::test]
async fn test_explicit_q_zero_with_wildcard_gzip_only_applies_nothing() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=0, *").await;
    assert_eq!(
        selected, None,
        "explicit gzip;q=0 must stay refused even with a wildcard when gzip is the only codec"
    );
}

/// #58: a bare wildcard (no explicit refusal) still re-enables a codec — this is
/// the pre-existing behaviour and must not regress.
#[tokio::test]
async fn test_bare_wildcard_still_enables_codec() {
    let selected = negotiate_encoding(json!(["gzip"]), "*").await;
    assert_eq!(selected.as_deref(), Some("gzip"));
}

/// #87: a present-but-unparseable q-value (`gzip;q=abc`) is ignored, so gzip
/// must NOT be selected when it is the only offered codec.
#[tokio::test]
async fn test_malformed_q_value_treated_as_not_acceptable() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=abc").await;
    assert_eq!(
        selected, None,
        "a garbage q-value must be ignored, not treated as q=1.0"
    );
}

/// #87: an empty q-value (`gzip;q=`) is likewise not acceptable.
#[tokio::test]
async fn test_empty_q_value_treated_as_not_acceptable() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=").await;
    assert_eq!(selected, None);
}

/// #87: a malformed q on one codec must not let it beat a well-formed,
/// genuinely-preferred codec. The invalid gzip member is ignored.
#[tokio::test]
async fn test_malformed_q_value_does_not_outrank_valid_codec() {
    // Server preference is gzip-first; without the fix gzip;q=abc would parse as
    // q=1.0 and win the tie. With the fix it is ignored, so br wins.
    let selected = negotiate_encoding(json!(["gzip", "br"]), "gzip;q=abc, br;q=1").await;
    assert_eq!(selected.as_deref(), Some("br"));
}

/// #87: `q=NaN` parses to a float in Rust but is not valid RFC 9110 syntax and
/// must be ignored so it neither wins selection nor poisons tie-break math.
#[tokio::test]
async fn test_nan_q_value_does_not_poison_selection() {
    // gzip;q=NaN must be excluded. br;q=0.5 is the only acceptable configured
    // codec, but it still loses to identity, which is acceptable by default at
    // q=1 (RFC 9110 §12.5.3) — so no gateway encoding is applied and the
    // response is sent uncoded.
    let selected = negotiate_encoding(json!(["gzip", "br"]), "gzip;q=NaN, br;q=0.5").await;
    assert_eq!(
        selected, None,
        "NaN q must be treated as not acceptable, and br;q=0.5 loses to the default identity quality"
    );

    // And when NaN is the only entry for the only codec, nothing is applied.
    let none = negotiate_encoding(json!(["gzip"]), "gzip;q=NaN").await;
    assert_eq!(none, None);
}

/// #87: a q-value above 1.0 is outside the RFC 9110 qvalue grammar. It is
/// ignored rather than clamped into an accepted coding.
#[tokio::test]
async fn test_out_of_range_q_value_is_ignored() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=5").await;
    assert_eq!(selected, None);
}

// ──────────────── #60: multi-member gzip request decompression ────────────────

/// Concatenated multi-member gzip is rejected by the shared content-coding
/// decoder (trailing bytes after the first member). Fail closed rather than
/// silently truncating to the first member.
#[tokio::test]
async fn test_multi_member_gzip_request_decompression_fails_closed() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let part_a = b"first gzip member payload; ";
    let part_b = b"second gzip member payload!";

    let mut compressed = Vec::new();
    for part in [part_a.as_slice(), part_b.as_slice()] {
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(part).unwrap();
        compressed.extend_from_slice(&encoder.finish().unwrap());
    }

    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let result = plugin
        .transform_request_body(&compressed, Some("application/octet-stream"), &headers)
        .await;
    assert!(
        result.is_none(),
        "concatenated multi-member gzip must fail closed instead of truncating"
    );
}

// ──────── #59: malformed compressed request body is rejected, not forwarded ────

/// Build a `RequestContext` carrying a `Content-Encoding` header and the given
/// raw request-body bytes exposed via `request_body_bytes` (as the proxy does
/// when buffering before `before_proxy`).
fn make_request_ctx_with_body(content_encoding: &str, body: &[u8]) -> RequestContext {
    let mut ctx = make_ctx(None);
    ctx.headers
        .insert("content-encoding".to_string(), content_encoding.to_string());
    ctx.request_body_bytes = Some(bytes::Bytes::copy_from_slice(body));
    ctx
}

#[tokio::test]
async fn test_empty_gzip_request_body_is_rejected() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_request_ctx_with_body("gzip", &[]);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), "0".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected Reject for empty gzip body, got {other:?}"),
    }
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_eq!(headers.get("content-length").map(String::as_str), Some("0"));
}

/// #59: a corrupt gzip request body must be rejected with a clean 400 in
/// `before_proxy`, and the `Content-Encoding`/`Content-Length` headers must NOT
/// be stripped (so we never forward a still-compressed body mislabeled as
/// plaintext to the backend).
#[tokio::test]
async fn test_corrupt_gzip_request_body_is_rejected() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    // Valid gzip magic but truncated/garbage stream -> decode fails.
    let corrupt = [0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00];
    let mut ctx = make_request_ctx_with_body("gzip", &corrupt);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), corrupt.len().to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected Reject for corrupt gzip body, got {other:?}"),
    }
    // Headers must remain intact since the request is being rejected — never
    // forward a body whose Content-Encoding was stripped while still compressed.
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert!(headers.contains_key("content-length"));
}

/// #59: an oversize (zip-bomb) gzip request body must also be rejected cleanly
/// rather than silently forwarded.
#[tokio::test]
async fn test_oversize_gzip_request_body_is_rejected() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({
        "decompress_request": true,
        "max_decompressed_request_size": 100,
    }));
    let big_body = vec![b'A'; 500];
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&big_body).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected Reject for oversize gzip body, got {other:?}"),
    }
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
}

/// #59: a VALID compressed request body must NOT be rejected — `before_proxy`
/// continues and strips the now-stale Content-Encoding/Content-Length headers.
#[tokio::test]
async fn test_valid_gzip_request_body_is_accepted_and_headers_stripped() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"a perfectly valid gzip request body";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !headers.contains_key("content-encoding"),
        "stale encoding must be stripped on success"
    );
    assert!(
        !headers.contains_key("content-length"),
        "stale length must be stripped on success"
    );
    assert_eq!(
        ctx.metadata
            .get("compression:request_encoding")
            .map(String::as_str),
        Some("gzip")
    );
}

#[tokio::test]
async fn test_request_cache_control_no_transform_still_decompresses_request_body() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"request body that would normally decompress";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());
    headers.insert("cache-control".to_string(), "no-transform".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        ctx.metadata
            .contains_key("compression:request_no_transform")
    );
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    assert_eq!(
        headers
            .get("x-ferrum-original-content-encoding")
            .map(String::as_str),
        Some("gzip")
    );

    let transformed = plugin
        .transform_request_body(&compressed, Some("application/octet-stream"), &headers)
        .await;
    assert_eq!(
        transformed.as_deref(),
        Some(original.as_slice()),
        "Cache-Control: no-transform must not bypass request decompression"
    );
}

#[tokio::test]
async fn test_original_request_no_transform_marker_restores_header_and_decompresses_body() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"request body that would normally decompress";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    ctx.metadata.insert(
        "ferrum:no_transform_request".to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        ctx.metadata
            .contains_key("compression:request_no_transform")
    );
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    assert_eq!(
        headers
            .get("x-ferrum-original-content-encoding")
            .map(String::as_str),
        Some("gzip")
    );
    assert_eq!(
        headers.get("cache-control").map(String::as_str),
        Some("no-transform"),
        "compression restores the original directive if an earlier hook removed it"
    );

    let transformed = plugin
        .transform_request_body(&compressed, Some("application/octet-stream"), &headers)
        .await;
    assert_eq!(
        transformed.as_deref(),
        Some(original.as_slice()),
        "original Cache-Control: no-transform must not bypass request decompression"
    );
}

#[tokio::test]
async fn test_request_no_transform_metadata_does_not_skip_context_aware_decode() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"request body that would normally decompress";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    ctx.metadata.insert(
        "compression:request_no_transform".to_string(),
        "true".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    // Production claims decode ownership in before_proxy before the transform
    // loop; the context-aware path is owner-gated.
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(
        ferrum_edge::_test_support::compression_ownership_for_test(&ctx)
            .0
            .is_some()
    );

    let transformed = plugin
        .transform_request_body_with_context(
            &mut ctx,
            &compressed,
            Some("application/octet-stream"),
            &headers,
        )
        .await;
    assert_eq!(
        transformed.as_deref(),
        Some(original.as_slice()),
        "request no-transform metadata must not leave gzip bytes opaque to final body hooks"
    );
}

#[test]
fn test_original_request_no_transform_marker_keeps_request_body_buffering() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_request_ctx_with_body("gzip", b"buffered gzip body");

    assert!(plugin.should_buffer_request_body(&ctx));

    ctx.metadata.insert(
        "ferrum:no_transform_request".to_string(),
        "true".to_string(),
    );

    assert!(
        plugin.should_buffer_request_body(&ctx),
        "stamped request no-transform must still buffer so compressed uploads are decoded before inspection"
    );
}

#[test]
fn test_unsupported_request_encoding_does_not_buffer_for_no_transform() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_request_ctx_with_body("zstd", b"streaming zstd body");

    ctx.metadata.insert(
        "ferrum:no_transform_request".to_string(),
        "true".to_string(),
    );

    assert!(
        !plugin.should_buffer_request_body(&ctx),
        "unsupported encodings must not be buffered when the compression plugin cannot decode them"
    );
}

/// #59: a double-compressed body whose decompressed payload is ITSELF valid
/// gzip (e.g. a client uploading a `.gz` file with `Content-Encoding: gzip`)
/// must be accepted — the gateway decodes exactly one transport layer and must
/// not false-positive reject it as "still compressed".
#[tokio::test]
async fn test_decompressed_payload_that_is_itself_gzip_is_accepted() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    // Inner gzip "file".
    let inner_plain = b"the original file contents";
    let mut inner_enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    inner_enc.write_all(inner_plain).unwrap();
    let inner_gz = inner_enc.finish().unwrap();
    // Transport-encode the .gz file with another gzip layer.
    let mut outer_enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    outer_enc.write_all(&inner_gz).unwrap();
    let outer_gz = outer_enc.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &outer_gz);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "one transport gzip layer is valid even when the payload is itself gzip"
    );

    // And the body transform yields exactly the inner .gz file bytes (one layer
    // removed), not a rejection or truncation.
    let decoded = plugin
        .transform_request_body(&outer_gz, Some("application/octet-stream"), &headers)
        .await
        .expect("one gzip layer should decode to the inner .gz bytes");
    assert_eq!(decoded, inner_gz);
}

/// #59: when the request body was NOT buffered before `before_proxy`
/// (`request_body_bytes` is None — e.g. an HBONE CONNECT tunnel), `before_proxy`
/// cannot validate. It must preserve both the encoded bytes and representation
/// headers rather than forwarding encoded bytes mislabeled as plaintext.
#[tokio::test]
async fn test_before_proxy_without_buffered_body_preserves_encoded_representation() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(None); // no request_body_bytes set
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), "42".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some("42")
    );
    assert!(
        plugin
            .transform_request_body_with_context(&mut ctx, b"encoded", None, &headers)
            .await
            .is_none(),
        "an unvalidated unbuffered body must pass through without rewrite"
    );
}

// ────────────── #2357: exact media-type content-type matching ──────────────
//
// The compression content-type whitelist must match only the trimmed media-type
// token before the first semicolon, ASCII case-insensitively, against the
// validated configured `content_types`. It must NOT use substring matching, so
// lexical near-misses and parameter-only occurrences are rejected.

/// Table of (response content-type, expected to compress) for the default
/// whitelist. Exercises exact types, mixed case, parameters, near-misses,
/// parameter-only occurrences, and malformed/empty values.
#[test]
fn test_content_type_whitelist_exact_matching() {
    let plugin = make_plugin(json!({}));
    let headers = HashMap::new();

    // (content_type, should_compress)
    let cases: &[(&str, bool)] = &[
        // Exact types in the default whitelist.
        ("application/json", true),
        ("application/javascript", true),
        ("application/xml", true),
        ("application/xhtml+xml", true),
        ("text/html", true),
        ("text/plain", true),
        ("text/css", true),
        ("text/xml", true),
        ("text/javascript", true),
        ("image/svg+xml", true),
        // Mixed case — ASCII case-insensitive match.
        ("Application/JSON", true),
        ("APPLICATION/JSON", true),
        ("Text/Html", true),
        ("APPLICATION/XML", true),
        // Parameters are stripped before matching.
        ("application/json; charset=utf-8", true),
        ("application/json; charset=UTF-8", true),
        ("application/json; charset=utf-8; boundary=xyz", true),
        ("text/html ; charset=utf-8", true),
        ("application/json;charset=utf-8", true),
        ("application/json\t; charset=utf-8", true),
        // Near-misses must NOT match.
        ("application/jsonp", false),
        ("application/json-patch-binary", false),
        ("application/jsonpatched", false),
        ("application/json2", false),
        ("text/htm", false),
        ("text/htmlx", false),
        ("text/javascriptish", false),
        // Parameter-only occurrences must NOT match.
        (
            "application/octet-stream; profile=\"application/json\"",
            false,
        ),
        ("application/octet-stream; charset=application/json", false),
        // Malformed / empty media-type tokens fail closed.
        ("", false),
        ("; charset=utf-8", false),
        (" ; charset=utf-8", false),
        (";", false),
        ("\t\n", false),
        // Non-whitelisted types.
        ("image/png", false),
        ("application/octet-stream", false),
        ("application/pdf", false),
        ("application/grpc", false),
        ("text/event-stream", false),
    ];

    for (content_type, should_compress) in cases {
        let ctx = make_ctx(Some("gzip"));
        // The public buffering-refinement hook and after_proxy both use the
        // same private content-type predicate.
        let buffered = plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some(content_type),
            200,
            &headers,
        );
        assert_eq!(
            buffered, *should_compress,
            "content_type={content_type:?}: buffering refinement disagrees with is_compressible_content_type (expected {should_compress}, got {buffered})",
        );
    }
}

/// Custom content_types whitelist must also use exact media-type matching.
#[test]
fn test_custom_content_type_whitelist_exact_matching() {
    let plugin = make_plugin(json!({
        "content_types": ["application/vnd.api+json", "text/csv"]
    }));
    let headers = HashMap::new();
    let ctx = make_ctx(Some("gzip"));

    let cases: &[(&str, bool)] = &[
        ("application/vnd.api+json", true),
        ("application/vnd.api+json; charset=utf-8", true),
        ("APPLICATION/VND.API+JSON", true),
        ("text/csv", true),
        ("text/csv; charset=us-ascii", true),
        // Near-misses must not match.
        ("application/vnd.api+jsonp", false),
        ("application/vnd.api+json-patch", false),
        ("application/vnd.api+jsonish", false),
        ("text/csvp", false),
        // Parameter-only occurrences must not match.
        (
            "application/octet-stream; profile=\"application/vnd.api+json\"",
            false,
        ),
        // Standard JSON is NOT in the custom whitelist.
        ("application/json", false),
        ("application/json; charset=utf-8", false),
    ];

    for (content_type, should_compress) in cases {
        let buffered = plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some(content_type),
            200,
            &headers,
        );
        assert_eq!(
            buffered, *should_compress,
            "content_type={content_type:?}: buffering refinement disagrees (expected {should_compress}, got {buffered})",
        );
    }
}

/// The same content-type predicate that controls buffering refinement must
/// also control `after_proxy` eligibility: a near-miss content-type that is
/// NOT whitelisted must not be compressed (no `Content-Encoding` set), while
/// an exact match with parameters IS compressed.
#[tokio::test]
async fn test_after_proxy_eligibility_matches_exact_whitelist() {
    let plugin = make_plugin(json!({
        "min_content_length": 10,
    }));

    // Near-miss: must NOT compress.
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/jsonp".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(
        !resp_headers.contains_key("content-encoding"),
        "near-miss 'application/jsonp' must not be compressed"
    );

    // Exact match with parameters: must compress.
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "content-type".to_string(),
        "application/json; charset=utf-8".to_string(),
    );
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert_eq!(
        resp_headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "exact match 'application/json; charset=utf-8' must be compressed"
    );

    // Parameter-only occurrence: must NOT compress.
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert(
        "content-type".to_string(),
        "application/octet-stream; profile=\"application/json\"".to_string(),
    );
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(
        !resp_headers.contains_key("content-encoding"),
        "parameter-only occurrence must not be compressed"
    );
}

/// Malformed/empty content-type values must fail closed (no compression, no
/// buffering) rather than matching or panicking.
#[tokio::test]
async fn test_malformed_content_type_fails_closed() {
    let plugin = make_plugin(json!({
        "min_content_length": 10,
    }));

    for content_type in ["", "; charset=utf-8", " ; ", ";"] {
        let mut ctx = make_ctx(Some("gzip"));
        let mut headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), content_type.to_string());
        resp_headers.insert("content-length".to_string(), "1000".to_string());

        plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        assert!(
            !resp_headers.contains_key("content-encoding"),
            "malformed content_type={content_type:?} must not be compressed"
        );
    }
}

/// A content-type absent from the response headers must fail closed (no
/// compression, no buffering).
#[test]
fn test_absent_content_type_fails_closed() {
    let plugin = make_plugin(json!({}));
    let ctx = make_ctx(Some("gzip"));
    let headers = HashMap::new();

    assert!(!plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &headers));
}

// ────────────────────── Integrity digests after compression (#2354) ──────────────────────

/// Actual gzip compression through the shared buffered transform lifecycle must
/// remove all four integrity fields case-insensitively while keeping the
/// gateway encoding and producing compressed wire bytes.
#[tokio::test]
async fn test_compression_transform_strips_stale_integrity_digests() {
    let plugin = Arc::new(make_plugin(json!({"min_content_length": 10}))) as Arc<dyn Plugin>;
    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let original = compressible_json_body();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_integrity_digests(&mut headers);
    headers.insert("etag".to_string(), "W/\"weak-origin\"".to_string());

    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    assert!(matches!(
        plugin.after_proxy(&mut ctx, status, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_integrity_digests_present(&headers);

    let mut body = bytes::Bytes::from(original.clone());
    let (replaced, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(!replaced);
    assert!(rewritten, "compression must rewrite the buffered body");
    assert_ne!(
        body, original,
        "wire bytes must be the compressed representation"
    );
    assert!(body.len() < original.len());
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "gateway Content-Encoding must survive integrity cleanup"
    );
    assert!(
        headers
            .get("vary")
            .is_some_and(|vary| vary.to_ascii_lowercase().contains("accept-encoding")),
        "Vary: Accept-Encoding must survive integrity cleanup"
    );
    let expected_len = body.len().to_string();
    assert_eq!(
        headers.get("content-length").map(String::as_str),
        Some(expected_len.as_str())
    );
    assert_integrity_digests_absent(&headers);
    assert!(
        headers.keys().all(|key| !key.eq_ignore_ascii_case("etag")),
        "weak ETag must not describe compressed bytes"
    );

    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(&body[..]);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("compressed body must round-trip");
    assert_eq!(decompressed, original);
}

/// Brotli path must strip the same integrity set after an actual transform.
#[tokio::test]
async fn test_brotli_compression_transform_strips_stale_integrity_digests() {
    let plugin = Arc::new(make_plugin(json!({"min_content_length": 10}))) as Arc<dyn Plugin>;
    let mut ctx = make_ctx(Some("br"));
    let mut req_headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let original = compressible_json_body();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_integrity_digests(&mut headers);

    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    assert!(matches!(
        plugin.after_proxy(&mut ctx, status, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("br")
    );

    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(rewritten);
    assert_ne!(body, original);
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("br")
    );
    assert_integrity_digests_absent(&headers);
}

/// When negotiation / eligibility declines compression, origin integrity fields
/// must remain untouched.
#[tokio::test]
async fn test_skipped_compression_preserves_integrity_digests() {
    let plugin = Arc::new(make_plugin(json!({"min_content_length": 10}))) as Arc<dyn Plugin>;

    // Strong ETag: skip compression, keep digests.
    {
        let mut ctx = make_ctx(Some("gzip"));
        let mut req_headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let original = compressible_json_body();
        let mut status = 200u16;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-length".to_string(), original.len().to_string());
        headers.insert("etag".to_string(), "\"strong-origin\"".to_string());
        insert_stale_integrity_digests(&mut headers);

        stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
        assert!(matches!(
            plugin.after_proxy(&mut ctx, status, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(!headers.contains_key("content-encoding"));

        let mut body = bytes::Bytes::from(original.clone());
        let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
            &[Arc::clone(&plugin)],
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
            false,
        )
        .await;
        assert!(!rewritten);
        assert_eq!(body, original);
        assert_integrity_digests_present(&headers);
        assert_eq!(
            headers.get("etag").map(String::as_str),
            Some("\"strong-origin\"")
        );
    }

    // Identity preferred: skip compression, keep digests.
    {
        let mut ctx = make_ctx(Some("identity;q=1, gzip;q=0.2"));
        let mut req_headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let original = compressible_json_body();
        let mut status = 200u16;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-length".to_string(), original.len().to_string());
        insert_stale_integrity_digests(&mut headers);

        stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
        assert!(matches!(
            plugin.after_proxy(&mut ctx, status, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(!headers.contains_key("content-encoding"));

        let mut body = bytes::Bytes::from(original.clone());
        let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
            &[Arc::clone(&plugin)],
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
            false,
        )
        .await;
        assert!(!rewritten);
        assert_eq!(body, original);
        assert_integrity_digests_present(&headers);
    }

    // Below min_content_length: skip compression, keep digests.
    {
        let plugin =
            Arc::new(make_plugin(json!({"min_content_length": 10_000}))) as Arc<dyn Plugin>;
        let mut ctx = make_ctx(Some("gzip"));
        let mut req_headers = HashMap::new();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let original = b"tiny".to_vec();
        let mut status = 200u16;
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-length".to_string(), original.len().to_string());
        insert_stale_integrity_digests(&mut headers);

        stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
        assert!(matches!(
            plugin.after_proxy(&mut ctx, status, &mut headers).await,
            PluginResult::Continue
        ));
        assert!(!headers.contains_key("content-encoding"));

        let mut body = bytes::Bytes::from(original.clone());
        let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
            &[plugin],
            &mut ctx,
            &mut status,
            &mut headers,
            &mut body,
            None,
            false,
        )
        .await;
        assert!(!rewritten);
        assert_eq!(body, original);
        assert_integrity_digests_present(&headers);
    }
}

/// A transform that returns `None` (no gateway commit) must leave digests alone.
#[tokio::test]
async fn test_compression_noop_transform_preserves_integrity_digests() {
    let plugin = Arc::new(make_plugin(json!({"min_content_length": 10}))) as Arc<dyn Plugin>;
    let mut ctx = make_ctx(Some("gzip"));
    // Do not run after_proxy: no gateway compression commit → transform returns None.
    let original = compressible_json_body();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    // Origin encoding without gateway commit metadata must not compress.
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    insert_stale_integrity_digests(&mut headers);

    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;

    assert!(!rewritten);
    assert_eq!(body, original);
    assert_integrity_digests_present(&headers);
}

/// Synthetic short-circuit publication uses the same finalize contract after an
/// actual compression rewrite.
#[tokio::test]
async fn test_synthetic_compression_transform_strips_stale_integrity_digests() {
    let plugin = Arc::new(make_plugin(json!({"min_content_length": 10}))) as Arc<dyn Plugin>;
    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let original = compressible_json_body();
    let mut status = 200u16;
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_integrity_digests(&mut headers);

    assert!(matches!(
        plugin.after_proxy(&mut ctx, status, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );

    let mut body = bytes::Bytes::from(original.clone());
    apply_synthetic_response_body_hooks_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
    )
    .await;

    assert_ne!(body, original);
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_integrity_digests_absent(&headers);
}

/// Digests that arrived only as trailers in the merged plugin view are removed
/// by finalize; buffered gRPC then retires the trailer channel copies.
#[tokio::test]
async fn test_trailer_integrity_digests_retired_after_compression_rewrite() {
    let plugin = Arc::new(make_plugin(json!({"min_content_length": 10}))) as Arc<dyn Plugin>;
    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let original = compressible_json_body();
    let mut status = 200u16;
    // Merged header+trailer compatibility view: digests present only via trailer names.
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_integrity_digests(&mut headers);

    stamp_original_response_metadata_for_test(&mut ctx, status, &headers);
    assert!(matches!(
        plugin.after_proxy(&mut ctx, status, &mut headers).await,
        PluginResult::Continue
    ));

    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &[plugin],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut body,
        None,
        false,
    )
    .await;
    assert!(rewritten);
    assert_integrity_digests_absent(&headers);

    // Wire trailers still hold the pre-rewrite values until the shared discard
    // boundary runs (H1/H2/H3 gRPC buffered paths). Digests must leave both maps.
    let mut trailers = HashMap::new();
    insert_stale_integrity_digests(&mut trailers);
    trailers.insert("grpc-status".to_string(), "0".to_string());
    discard_grpc_application_trailers_after_body_rewrite_for_test(&mut headers, &mut trailers, &[]);
    assert_eq!(
        trailers,
        HashMap::from([("grpc-status".to_string(), "0".to_string())]),
        "application trailer digests must be retired; terminal status preserved"
    );
    assert_integrity_digests_absent(&headers);
}
// ────────────────────── Multi-instance ownership (#2353) ──────────────────────

fn gzip_bytes(plaintext: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plaintext).unwrap();
    encoder.finish().unwrap()
}

fn gunzip_bytes(compressed: &[u8]) -> Vec<u8> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    let mut decoder = GzDecoder::new(compressed);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).unwrap();
    out
}

async fn run_before_proxy_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> PluginResult {
    for plugin in plugins {
        match plugin.before_proxy(ctx, headers).await {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    PluginResult::Continue
}

async fn run_after_proxy_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    response_headers: &mut HashMap<String, String>,
) -> PluginResult {
    for plugin in plugins {
        match plugin
            .after_proxy(ctx, response_status, response_headers)
            .await
        {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    PluginResult::Continue
}

/// Mirror the production H1/H2 / native H3 request-body transform loop.
async fn run_request_body_transform_loop(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
    body: Vec<u8>,
) -> Vec<u8> {
    let content_type = headers.get("content-type").map(String::as_str);
    let mut current = body;
    for plugin in plugins {
        if !plugin.modifies_request_body() {
            continue;
        }
        if let Some(transformed) = plugin
            .transform_request_body_with_context(ctx, &current, content_type, headers)
            .await
        {
            current = transformed;
        }
    }
    current
}

#[tokio::test]
async fn test_multi_instance_response_single_coding_layer() {
    // Two gzip instances must advertise one Content-Encoding and emit one layer.
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(json!({
            "algorithms": ["gzip"],
            "min_content_length": 10
        }))),
        Arc::new(make_plugin(json!({
            "algorithms": ["gzip"],
            "min_content_length": 10
        }))),
        Arc::new(make_plugin(json!({
            "algorithms": ["br"],
            "min_content_length": 10
        }))),
    ];

    let original = compressible_json_body();
    let mut ctx = make_ctx(Some("gzip, br"));
    let mut req_headers = HashMap::new();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut req_headers).await,
        PluginResult::Continue
    ));

    let mut status = 200u16;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), original.len().to_string());
    insert_stale_integrity_digests(&mut resp_headers);
    stamp_original_response_metadata_for_test(&mut ctx, status, &resp_headers);

    assert!(matches!(
        run_after_proxy_chain(&plugins, &mut ctx, status, &mut resp_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        resp_headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "first committing instance wins; later configs must not stack encodings"
    );
    assert!(
        ferrum_edge::_test_support::compression_ownership_for_test(&ctx)
            .1
            .is_some()
    );
    assert_eq!(
        ctx.metadata
            .get("compression:algorithm")
            .map(String::as_str),
        Some("gzip")
    );

    let mut body = bytes::Bytes::from(original.clone());
    let (_, rewritten) = transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut resp_headers,
        &mut body,
        None,
        false,
    )
    .await;
    assert!(rewritten);
    assert_eq!(
        resp_headers.get("content-encoding").map(String::as_str),
        Some("gzip")
    );
    assert_eq!(gunzip_bytes(&body), original);
    assert_integrity_digests_absent(&resp_headers);
}

#[tokio::test]
async fn test_multi_instance_response_order_selects_brotli_first() {
    // Configured order: brotli-only then gzip-only. Accept-Encoding prefers br.
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(json!({
            "algorithms": ["br"],
            "min_content_length": 10
        }))),
        Arc::new(make_plugin(json!({
            "algorithms": ["gzip"],
            "min_content_length": 10
        }))),
    ];

    let original = compressible_json_body();
    let mut ctx = make_ctx(Some("br, gzip"));
    let mut req_headers = HashMap::new();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut req_headers).await,
        PluginResult::Continue
    ));

    let mut status = 200u16;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), original.len().to_string());
    stamp_original_response_metadata_for_test(&mut ctx, status, &resp_headers);
    assert!(matches!(
        run_after_proxy_chain(&plugins, &mut ctx, status, &mut resp_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        resp_headers.get("content-encoding").map(String::as_str),
        Some("br")
    );

    let mut body = bytes::Bytes::from(original.clone());
    transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut resp_headers,
        &mut body,
        None,
        false,
    )
    .await;
    let mut decoded = Vec::new();
    brotli::BrotliDecompress(&mut &body[..], &mut decoded).unwrap();
    assert_eq!(decoded, original);
}

#[tokio::test]
async fn test_multi_instance_identity_then_later_instance_may_compress() {
    // First instance cannot produce gzip (algorithms=[br] only) so nominates
    // identity; second instance with gzip may still commit a single layer.
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(json!({
            "algorithms": ["br"],
            "min_content_length": 10
        }))),
        Arc::new(make_plugin(json!({
            "algorithms": ["gzip"],
            "min_content_length": 10
        }))),
    ];

    let original = compressible_json_body();
    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut req_headers).await,
        PluginResult::Continue
    ));

    let mut status = 200u16;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), original.len().to_string());
    stamp_original_response_metadata_for_test(&mut ctx, status, &resp_headers);
    assert!(matches!(
        run_after_proxy_chain(&plugins, &mut ctx, status, &mut resp_headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        resp_headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "identity-only earlier instance must not block a later compress"
    );

    let mut body = bytes::Bytes::from(original.clone());
    transform_buffered_response_body_with_deadline_full_for_test(
        &plugins,
        &mut ctx,
        &mut status,
        &mut resp_headers,
        &mut body,
        None,
        false,
    )
    .await;
    assert_eq!(gunzip_bytes(&body), original);
}

#[tokio::test]
async fn test_multi_instance_request_decode_exactly_once() {
    let original = b"{\"hello\":\"multi-instance upload\"}";
    let compressed = gzip_bytes(original);
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(json!({"decompress_request": true}))),
        Arc::new(make_plugin(json!({"decompress_request": true}))),
        Arc::new(make_plugin(json!({"decompress_request": false}))),
    ];

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());

    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(
        !headers.contains_key("content-encoding"),
        "owner strips public encoding exactly once"
    );
    assert_eq!(
        headers
            .get("x-ferrum-original-content-encoding")
            .map(String::as_str),
        Some("gzip"),
        "siblings must not delete the owner's internal marker"
    );
    assert!(
        ferrum_edge::_test_support::compression_ownership_for_test(&ctx)
            .0
            .is_some()
    );

    let decoded = run_request_body_transform_loop(&plugins, &mut ctx, &headers, compressed).await;
    assert_eq!(decoded, original);
}

#[tokio::test]
async fn test_multi_instance_request_second_instance_claims_when_first_disabled() {
    let original = b"claimed by second compression instance";
    let compressed = gzip_bytes(original);
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(json!({"decompress_request": false}))),
        Arc::new(make_plugin(json!({"decompress_request": true}))),
    ];

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(!headers.contains_key("content-encoding"));
    let decoded = run_request_body_transform_loop(&plugins, &mut ctx, &headers, compressed).await;
    assert_eq!(decoded, original);
}

#[tokio::test]
async fn test_multi_instance_malformed_upload_rejects_without_stripping() {
    let corrupt = [0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00];
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(make_plugin(json!({"decompress_request": true}))),
        Arc::new(make_plugin(json!({"decompress_request": true}))),
    ];

    let mut ctx = make_request_ctx_with_body("gzip", &corrupt);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), corrupt.len().to_string());

    match run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("expected Reject for corrupt upload, got {other:?}"),
    }
    assert_eq!(
        headers.get("content-encoding").map(String::as_str),
        Some("gzip"),
        "failed claim must not strip encoding metadata"
    );
    assert!(
        ferrum_edge::_test_support::compression_ownership_for_test(&ctx)
            .0
            .is_none()
    );
}

#[tokio::test]
async fn test_multi_instance_plugin_cache_reload_preserves_ownership() {
    use ferrum_edge::config::types::{PluginAssociation, PluginConfig, PluginScope};
    use ferrum_edge::config_delta::ConfigDelta;

    fn gateway_with(
        ids_and_configs: &[(&str, serde_json::Value, u16)],
    ) -> ferrum_edge::config::types::GatewayConfig {
        let mut proxy = create_test_proxy();
        proxy.id = "p1".to_string();
        proxy.plugins = ids_and_configs
            .iter()
            .map(|(id, _, _)| PluginAssociation {
                plugin_config_id: (*id).to_string(),
            })
            .collect();
        ferrum_edge::config::types::GatewayConfig {
            version: "1".to_string(),
            proxies: vec![proxy],
            consumers: vec![],
            plugin_configs: ids_and_configs
                .iter()
                .map(|(id, config, priority)| PluginConfig {
                    id: (*id).to_string(),
                    namespace: ferrum_edge::config::types::default_namespace(),
                    plugin_name: "compression".to_string(),
                    config: config.clone(),
                    scope: PluginScope::Proxy,
                    proxy_id: Some("p1".to_string()),
                    enabled: true,
                    priority_override: Some(*priority),
                    api_spec_id: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                })
                .collect(),
            upstreams: vec![],
            loaded_at: chrono::Utc::now(),
            known_namespaces: Vec::new(),
            ..Default::default()
        }
    }

    let seed = gateway_with(&[
        (
            "comp-a",
            json!({"algorithms": ["gzip"], "min_content_length": 10, "decompress_request": true}),
            4050,
        ),
        (
            "comp-b",
            json!({"algorithms": ["br"], "min_content_length": 10, "decompress_request": true}),
            4060,
        ),
    ]);
    let cache = ferrum_edge::PluginCache::new(&seed).expect("seed compression cache");
    let compression: Vec<_> = cache
        .get_plugins("ferrum", "p1")
        .iter()
        .filter(|p| p.name() == "compression")
        .cloned()
        .collect();
    assert_eq!(compression.len(), 2);

    let original = compressible_json_body();
    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    assert!(matches!(
        run_before_proxy_chain(&compression, &mut ctx, &mut req_headers).await,
        PluginResult::Continue
    ));
    let mut status = 200u16;
    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "application/json".to_string());
    resp_headers.insert("content-length".to_string(), original.len().to_string());
    stamp_original_response_metadata_for_test(&mut ctx, status, &resp_headers);
    assert!(matches!(
        run_after_proxy_chain(&compression, &mut ctx, status, &mut resp_headers).await,
        PluginResult::Continue
    ));
    let mut body = bytes::Bytes::from(original.clone());
    transform_buffered_response_body_with_deadline_full_for_test(
        &compression,
        &mut ctx,
        &mut status,
        &mut resp_headers,
        &mut body,
        None,
        false,
    )
    .await;
    assert_eq!(gunzip_bytes(&body), original);

    let rebuilt = gateway_with(&[
        (
            "comp-a",
            json!({"algorithms": ["gzip"], "min_content_length": 10, "decompress_request": true}),
            4050,
        ),
        (
            "comp-b",
            json!({"algorithms": ["br"], "min_content_length": 10, "decompress_request": true}),
            4060,
        ),
        (
            "comp-c",
            json!({"algorithms": ["gzip", "br"], "min_content_length": 10, "decompress_request": true}),
            4070,
        ),
    ]);
    let delta = ConfigDelta::compute(&seed, &rebuilt);
    let proxy_ids = delta.proxy_ids_needing_plugin_rebuild(&seed, &rebuilt);
    cache
        .apply_delta(
            &rebuilt,
            &proxy_ids,
            &delta.removed_proxy_ids,
            delta.global_plugin_configs_changed,
        )
        .expect("compression multi-instance reload");

    let after_compression: Vec<_> = cache
        .get_plugins("ferrum", "p1")
        .iter()
        .filter(|p| p.name() == "compression")
        .cloned()
        .collect();
    assert_eq!(after_compression.len(), 3);

    let upload = b"post-reload decode";
    let compressed = gzip_bytes(upload);
    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());
    assert!(matches!(
        run_before_proxy_chain(&after_compression, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let decoded =
        run_request_body_transform_loop(&after_compression, &mut ctx, &headers, compressed).await;
    assert_eq!(decoded, upload);
}

#[test]
fn test_h1_h2_h3_paths_share_multi_instance_body_transform_loops() {
    // Behavioral coverage above drives the shared helpers. Pin that each
    // production protocol surface reaches those same sequential loops so
    // multi-instance ownership cannot diverge per protocol.
    let h1_h2 = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/server.rs");
    let h3_cross = include_str!("../../../src/http3/cross_protocol.rs");

    assert!(
        h1_h2.contains("apply_request_body_plugins_with_context(")
            && h1_h2.contains("transform_request_body_with_context(")
            && h1_h2.contains("transform_buffered_response_body_with_deadline(")
            && h1_h2.contains("transform_response_body_with_context(")
            && h1_h2.contains("apply_buffered_request_body_normalization_before_before_proxy("),
        "H1/H2 must use the shared request/response body transform loops and pre-before_proxy normalization"
    );
    assert!(
        h3.contains("apply_request_body_plugins_with_context(")
            && h3.contains("transform_buffered_response_body_with_deadline(")
            && h3.contains("apply_buffered_request_body_normalization_before_before_proxy("),
        "native H3 must use the shared body transform helpers and pre-before_proxy normalization"
    );
    assert!(
        h3_cross.contains("apply_request_body_plugins_with_context("),
        "H3 cross-protocol must use the shared request-body transform helper"
    );
}

// ── Compression audit follow-up (#3059, #3060, #3071, #3072) ───────────────

#[test]
fn test_max_decompressed_request_size_hard_maximum_rejected() {
    use ferrum_edge::plugins::compression::HARD_MAX_DECOMPRESSED_REQUEST_SIZE;

    let over = HARD_MAX_DECOMPRESSED_REQUEST_SIZE.saturating_add(1);
    let result = CompressionPlugin::new(&json!({
        "decompress_request": true,
        "max_decompressed_request_size": over
    }));
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("values above the hard maximum must fail admission"),
    };
    assert!(err.contains("hard maximum"), "got: {err}");
}

#[test]
fn test_max_decompressed_request_size_cross_checks_request_body_limit() {
    let result = CompressionPlugin::new_with_algorithm_support_and_body_limit(
        &json!({
            "decompress_request": true,
            "max_decompressed_request_size": 2_000_000
        }),
        true,
        true,
        1_000_000,
    );
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("decompressed ceiling must not exceed the request body limit"),
    };
    assert!(
        err.contains("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES"),
        "got: {err}"
    );
}

#[test]
fn test_response_only_compression_ignores_unused_decompression_body_cross_check() {
    CompressionPlugin::new_with_algorithm_support_and_body_limit(
        &json!({
            "decompress_request": false
        }),
        true,
        true,
        1_000_000,
    )
    .expect("response-only compression must not reject an unused decompression default");
}

#[test]
fn test_max_decompressed_request_size_at_hard_maximum_accepted() {
    use ferrum_edge::plugins::compression::HARD_MAX_DECOMPRESSED_REQUEST_SIZE;

    CompressionPlugin::new(&json!({
        "decompress_request": true,
        "max_decompressed_request_size": HARD_MAX_DECOMPRESSED_REQUEST_SIZE
    }))
    .expect("exact hard maximum must be accepted when no body limit is set");
}

#[tokio::test]
async fn test_high_ratio_amplification_aborts_early() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    // Highly compressible zeros: a tiny gzip expands far past 1024:1 under a
    // generous absolute size cap, so the amplification ratio must trip first.
    let plugin = make_plugin(json!({
        "decompress_request": true,
        "max_decompressed_request_size": 16 * 1024 * 1024
    }));
    // Four MiB sits on the 1024:1 boundary with some flate2/miniz versions
    // once gzip framing is included. Eight MiB keeps the fixture decisively
    // beyond the policy ratio without approaching the absolute cap.
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(&zeros).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(
        compressed
            .len()
            .checked_mul(1024)
            .is_some_and(|limit| limit < zeros.len()),
        "fixture must exceed the 1024:1 amplification ratio (compressed={})",
        compressed.len()
    );

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut body = compressed.clone();
    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;
    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 400,
                ..
            }
        ),
        "high-ratio zip bombs must fail closed, got {result:?}"
    );
}

#[tokio::test]
async fn test_global_gates_partial_disable_keeps_remaining_codec() {
    let plugin = CompressionPlugin::new_with_algorithm_support(
        &json!({"algorithms": ["gzip", "br"], "remove_accept_encoding": true}),
        false,
        true,
    )
    .expect("Brotli-only remains usable");

    let mut ctx = make_ctx(Some("gzip, br"));
    let mut headers = HashMap::new();
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        !headers.contains_key("accept-encoding"),
        "usable response codec may still strip Accept-Encoding"
    );

    let mut resp = HashMap::new();
    resp.insert("content-type".to_string(), "application/json".to_string());
    resp.insert("content-length".to_string(), "1000".to_string());
    plugin.after_proxy(&mut ctx, 200, &mut resp).await;
    assert_eq!(resp.get("content-encoding").map(String::as_str), Some("br"));
}

#[tokio::test]
async fn test_content_encoding_ows_is_trimmed_and_decoded() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"ows-trimmed content-encoding";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), " gzip ".to_string());
    let mut body = compressed.clone();
    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body.as_slice(), original.as_slice());
}

#[tokio::test]
async fn test_request_decompression_is_bounded_by_route_size_ceiling() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = vec![b'a'; 256];
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();
    assert!(
        compressed.len() < 64,
        "fixture must fit under the encoded route ceiling"
    );

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    ctx.route_request_body_limit_bytes = Some(64);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut body = compressed.clone();

    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 400,
                ..
            }
        ),
        "plaintext larger than the route ceiling must fail before retention, got {result:?}"
    );
    assert_eq!(
        body, compressed,
        "failed decode must not replace the bounded wire body"
    );
    assert!(
        headers.contains_key("content-encoding"),
        "failed decode must preserve representation metadata"
    );
}

#[tokio::test]
async fn test_request_decompression_exact_route_boundary_passes() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = vec![b'a'; 64];
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&original).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    ctx.route_request_body_limit_bytes = Some(64);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    let mut body = compressed;

    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;

    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(body, original);
}

#[tokio::test]
async fn test_content_encoding_chain_decodes_in_reverse_order() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"stacked gzip then brotli";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let gzip_buf = encoder.finish().unwrap();
    let mut br_buf = Vec::new();
    let params = brotli::enc::BrotliEncoderParams::default();
    brotli::BrotliCompress(&mut &gzip_buf[..], &mut br_buf, &params).unwrap();

    let mut ctx = make_request_ctx_with_body("gzip, br", &br_buf);
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip, br".to_string());
    let mut body = br_buf.clone();
    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(body.as_slice(), original.as_slice());
    assert_eq!(
        ctx.metadata
            .get("compression:request_encoding")
            .map(String::as_str),
        Some("gzip, br")
    );
}

#[tokio::test]
async fn test_content_encoding_identity_only_strips_without_body_rewrite() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_request_ctx_with_body("identity", b"plain");
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "identity".to_string());
    let mut body = b"plain".to_vec();
    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(body, b"plain");
    assert!(!headers.contains_key("content-encoding"));
}

#[tokio::test]
async fn test_content_encoding_duplicate_supported_members_decode() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"double gzip chain";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let once = encoder.finish().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&once).unwrap();
    let twice = encoder.finish().unwrap();

    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip, gzip".to_string());
    let mut ctx = make_request_ctx_with_body("gzip, gzip", &twice);
    let mut body = twice.clone();
    let result = plugin
        .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
        .await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert_eq!(body.as_slice(), original.as_slice());
}

#[tokio::test]
async fn test_content_encoding_malformed_and_unsupported_fail_closed() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    for ce in ["gzip,", ",gzip", "gzip;q=1", "zstd", "gzip, identity"] {
        let mut ctx = make_request_ctx_with_body(ce, b"x");
        let mut headers = HashMap::new();
        headers.insert("content-encoding".to_string(), ce.to_string());
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 400,
                    ..
                }
            ),
            "Content-Encoding '{ce}' must fail closed, got {result:?}"
        );
    }
}

#[tokio::test]
async fn test_codec_admission_saturation_rejects_request_decode() {
    use ferrum_edge::plugins::compression::{compression_codec_metrics, with_test_codec_budget};
    use flate2::write::GzEncoder;
    use std::io::Write;

    with_test_codec_budget(0, || async {
        let before = compression_codec_metrics();

        let plugin = make_plugin(json!({"decompress_request": true}));
        let original = b"saturation fixture";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut ctx = make_request_ctx_with_body("gzip", &compressed);
        let mut headers = HashMap::new();
        headers.insert("content-encoding".to_string(), "gzip".to_string());
        let mut body = compressed;
        let result = plugin
            .normalize_buffered_request_body_before_before_proxy(&mut ctx, &mut headers, &mut body)
            .await;
        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 503,
                    ..
                }
            ),
            "saturated codec budget must reject request decode, got {result:?}"
        );
        let after = compression_codec_metrics();
        assert!(after.saturated > before.saturated);
    })
    .await;
}

#[tokio::test]
async fn test_codec_admission_saturation_skips_response_transform() {
    use ferrum_edge::plugins::compression::with_test_codec_budget;

    with_test_codec_budget(0, || async {
        let plugin = make_plugin(json!({"min_content_length": 10}));
        let mut ctx = make_ctx(Some("gzip"));
        let mut headers = HashMap::new();
        headers.insert("accept-encoding".to_string(), "gzip".to_string());
        plugin.before_proxy(&mut ctx, &mut headers).await;

        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "application/json".to_string());
        resp.insert("content-length".to_string(), "1000".to_string());
        let result = plugin.after_proxy(&mut ctx, 200, &mut resp).await;
        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(
            resp.get("content-encoding").map(String::as_str),
            Some("gzip")
        );
        assert!(
            plugin
                .transform_response_body_with_context(
                    &mut ctx,
                    br#"{"message":"large enough response"}"#,
                    Some("application/json"),
                    &resp,
                )
                .await
                .is_none(),
            "saturated codec budget must decline the response transform"
        );
    })
    .await;
}

#[tokio::test]
async fn test_response_buffer_reservation_does_not_starve_request_decode() {
    use ferrum_edge::plugins::compression::{
        with_test_codec_budget, with_test_response_buffer_budget,
    };
    use flate2::write::GzEncoder;
    use std::io::Write;

    with_test_codec_budget(1, || async {
        with_test_response_buffer_budget(1, || async {
            let response_plugin = make_plugin(json!({}));
            let mut slow_response = make_ctx(Some("gzip"));
            before_proxy_with_accept_encoding(&response_plugin, &mut slow_response, Some("gzip"))
                .await;
            assert!(
                ferrum_edge::_test_support::compression_response_admission_reserved_for_test(
                    &slow_response
                )
            );

            let request_plugin = make_plugin(json!({"decompress_request": true}));
            let original = b"request decode remains independently admitted";
            let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(original).unwrap();
            let compressed = encoder.finish().unwrap();
            let mut ctx = make_request_ctx_with_body("gzip", &compressed);
            let mut headers = HashMap::from([("content-encoding".to_string(), "gzip".to_string())]);
            let mut body = compressed;

            let result = request_plugin
                .normalize_buffered_request_body_before_before_proxy(
                    &mut ctx,
                    &mut headers,
                    &mut body,
                )
                .await;
            assert!(matches!(result, PluginResult::Continue));
            assert_eq!(body, original);
        })
        .await;
    })
    .await;
}

// ───────── Response-buffer negotiation + independent admission ─────────

/// Run `before_proxy` with the Accept-Encoding staged in the header param (the
/// production shape) so the response-admission reservation observes the saved
/// snapshot exactly as it does in the proxy.
async fn before_proxy_with_accept_encoding(
    plugin: &CompressionPlugin,
    ctx: &mut RequestContext,
    accept_encoding: Option<&str>,
) {
    let mut headers = HashMap::new();
    if let Some(ae) = accept_encoding {
        headers.insert("accept-encoding".to_string(), ae.to_string());
    }
    assert!(matches!(
        plugin.before_proxy(ctx, &mut headers).await,
        PluginResult::Continue
    ));
}

#[test]
fn test_should_buffer_negotiates_accept_encoding_not_mere_presence() {
    // Response buffering must reflect real negotiation, not the presence of an
    // Accept-Encoding header: identity, unsupported-only, and all-`q=0` requests
    // have nothing this instance can compress, so they must stream.
    let plugin = make_plugin(json!({}));
    for ae in ["identity", "deflate", "zstd", "gzip;q=0, br;q=0", "*;q=0"] {
        let ctx = make_ctx(Some(ae));
        assert!(
            !plugin.should_buffer_response_body(&ctx),
            "Accept-Encoding {ae:?} selects no supported coding and must not buffer"
        );
    }
    for ae in ["gzip", "br", "gzip;q=0, br", "identity;q=0, gzip;q=0.2"] {
        let ctx = make_ctx(Some(ae));
        assert!(
            plugin.should_buffer_response_body(&ctx),
            "Accept-Encoding {ae:?} selects a supported coding and must buffer"
        );
    }
}

#[test]
fn test_should_buffer_respects_configured_algorithms() {
    // A gzip-only instance must not buffer a brotli-only request (nothing it can
    // produce), even though an Accept-Encoding header is present.
    let plugin = make_plugin(json!({"algorithms": ["gzip"]}));
    assert!(!plugin.should_buffer_response_body(&make_ctx(Some("br"))));
    assert!(plugin.should_buffer_response_body(&make_ctx(Some("gzip"))));
}

#[tokio::test]
async fn test_before_proxy_reserves_admission_for_supported_coding() {
    use ferrum_edge::_test_support::{
        compression_response_admission_declined_for_test,
        compression_response_admission_reserved_for_test,
    };
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
    assert!(
        compression_response_admission_reserved_for_test(&ctx),
        "a supported coding must reserve response-buffer admission in before_proxy"
    );
    assert!(!compression_response_admission_declined_for_test(&ctx));
}

#[tokio::test]
async fn test_before_proxy_does_not_reserve_for_unnegotiable_encodings() {
    use ferrum_edge::_test_support::{
        compression_response_admission_declined_for_test,
        compression_response_admission_reserved_for_test,
    };
    let plugin = make_plugin(json!({}));
    for ae in [
        Some("identity"),
        Some("deflate"),
        Some("gzip;q=0, br;q=0"),
        None,
    ] {
        let mut ctx = make_ctx(ae);
        before_proxy_with_accept_encoding(&plugin, &mut ctx, ae).await;
        assert!(
            !compression_response_admission_reserved_for_test(&ctx),
            "Accept-Encoding {ae:?} must not reserve response-buffer admission"
        );
        assert!(
            !compression_response_admission_declined_for_test(&ctx),
            "no reservation was attempted for {ae:?}, so it must not be marked declined"
        );
    }
}

#[tokio::test]
async fn test_unsafe_global_response_limits_decline_compression_before_buffering() {
    use ferrum_edge::_test_support::{
        compression_response_admission_declined_for_test,
        compression_response_admission_reserved_for_test,
    };
    use ferrum_edge::plugins::compression::HARD_MAX_COMPRESSIBLE_RESPONSE_SIZE;

    let plugin = make_plugin(json!({}));
    for limit in [0, HARD_MAX_COMPRESSIBLE_RESPONSE_SIZE + 1] {
        let mut ctx = make_ctx(Some("gzip"));
        ctx.max_response_body_size_bytes = limit;
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
        assert!(
            compression_response_admission_declined_for_test(&ctx),
            "unsafe response limit {limit} must decline compression admission"
        );
        assert!(!compression_response_admission_reserved_for_test(&ctx));
        assert!(
            !plugin.should_buffer_response_body(&ctx),
            "unsafe response limit {limit} must stream identity"
        );

        let mut response_headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "1000".to_string()),
        ]);
        assert!(matches!(
            plugin
                .after_proxy(&mut ctx, 200, &mut response_headers)
                .await,
            PluginResult::Continue
        ));
        assert!(
            !response_headers.contains_key("content-encoding"),
            "unsafe response limit {limit} must not commit compression"
        );

        let accept_encoding = "gzip, identity;q=0";
        let mut identity_barred_ctx = make_ctx(Some(accept_encoding));
        identity_barred_ctx.max_response_body_size_bytes = limit;
        before_proxy_with_accept_encoding(&plugin, &mut identity_barred_ctx, Some(accept_encoding))
            .await;
        assert!(
            !plugin.should_buffer_response_body(&identity_barred_ctx),
            "unsafe response limit {limit} must not buffer when identity is prohibited"
        );
        let mut identity_barred_headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-length".to_string(), "1000".to_string()),
        ]);
        match plugin
            .after_proxy(&mut identity_barred_ctx, 200, &mut identity_barred_headers)
            .await
        {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 406),
            other => panic!(
                "expected 406 when identity is barred under unsafe response limit {limit}, got {other:?}"
            ),
        }
        assert!(!identity_barred_headers.contains_key("content-encoding"));
    }

    let mut ceiling_ctx = make_ctx(Some("gzip"));
    ceiling_ctx.max_response_body_size_bytes = HARD_MAX_COMPRESSIBLE_RESPONSE_SIZE;
    before_proxy_with_accept_encoding(&plugin, &mut ceiling_ctx, Some("gzip")).await;
    assert!(
        compression_response_admission_reserved_for_test(&ceiling_ctx),
        "the exact compression safety ceiling must remain admissible"
    );
    assert!(plugin.should_buffer_response_body(&ceiling_ctx));
}

#[tokio::test]
async fn test_head_does_not_reserve_or_buffer_response() {
    use ferrum_edge::_test_support::compression_response_admission_reserved_for_test;
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("gzip"));
    ctx.method = "HEAD".to_string();
    before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
    assert!(
        !compression_response_admission_reserved_for_test(&ctx),
        "HEAD carries no re-encodable wire body and must not reserve admission"
    );
    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_saturation_before_buffering_streams_identity() {
    use ferrum_edge::_test_support::{
        compression_response_admission_declined_for_test,
        compression_response_admission_reserved_for_test,
    };
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    with_test_response_buffer_budget(0, || async {
        let plugin = make_plugin(json!({"min_content_length": 10}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;

        // Admission was unavailable: no reservation, marked declined, and the
        // body must stream (never enter the compression-only buffered path).
        assert!(!compression_response_admission_reserved_for_test(&ctx));
        assert!(compression_response_admission_declined_for_test(&ctx));
        assert!(
            !plugin.should_buffer_response_body(&ctx),
            "a request that could not reserve admission must stream, not buffer"
        );

        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "application/json".to_string());
        resp.insert("content-length".to_string(), "1000".to_string());
        // Identity is acceptable, so after_proxy serves it without reacquiring.
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp).await,
            PluginResult::Continue
        ));
        assert!(!resp.contains_key("content-encoding"));
    })
    .await;
}

#[tokio::test]
async fn test_saturation_before_buffering_fails_closed_when_identity_barred() {
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    with_test_response_buffer_budget(0, || async {
        let plugin = make_plugin(json!({"min_content_length": 10}));
        let mut ctx = make_ctx(Some("gzip, identity;q=0"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip, identity;q=0")).await;
        assert!(
            !plugin.should_buffer_response_body(&ctx),
            "declined admission must not buffer even when identity is prohibited"
        );

        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "application/json".to_string());
        resp.insert("content-length".to_string(), "1000".to_string());
        // Identity is prohibited and no coding can be produced: fail closed.
        match plugin.after_proxy(&mut ctx, 200, &mut resp).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 406),
            other => panic!("expected 406 when identity is barred under saturation, got {other:?}"),
        }
        assert!(!resp.contains_key("content-encoding"));
    })
    .await;
}

#[tokio::test]
async fn test_after_proxy_consumes_reserved_buffer_permit_without_reacquiring() {
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    // A single-slot buffer budget proves reuse: the reservation drains the only slot,
    // so a commit can only succeed by consuming the reserved permit (a fresh
    // acquire would find the budget empty and decline to Content-Encoding).
    with_test_response_buffer_budget(1, || async {
        let plugin = make_plugin(json!({"min_content_length": 10}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;

        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "application/json".to_string());
        resp.insert("content-length".to_string(), "1000".to_string());
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp).await,
            PluginResult::Continue
        ));
        assert_eq!(
            resp.get("content-encoding").map(String::as_str),
            Some("gzip"),
            "after_proxy must commit by consuming the reserved buffer permit, not reacquiring"
        );
        // The reserved buffer permit is still held until the body transform
        // obtains the independent codec CPU permit.
        assert!(
            ferrum_edge::_test_support::take_compression_response_buffer_permit_for_test(&mut ctx)
                .is_some()
        );
    })
    .await;
}

#[tokio::test]
async fn test_ineligible_response_keeps_buffer_slot_for_retained_body() {
    use ferrum_edge::_test_support::{
        compression_response_admission_reserved_for_test,
        take_compression_response_buffer_permit_for_test,
    };
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    // budget=1: an ineligible response must not free the slot while the
    // already-admitted body remains resident (a sibling may still encode it).
    with_test_response_buffer_budget(1, || async {
        let plugin = make_plugin(json!({"min_content_length": 10}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
        assert!(compression_response_admission_reserved_for_test(&ctx));

        // A non-compressible content type: after_proxy declines to encode but
        // must leave the reserved permit on the context (ownership cleared).
        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "image/png".to_string());
        resp.insert("content-length".to_string(), "5000".to_string());
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp).await,
            PluginResult::Continue
        ));
        assert!(!resp.contains_key("content-encoding"));
        assert!(
            !compression_response_admission_reserved_for_test(&ctx),
            "an ineligible instance must clear admission ownership"
        );

        // Concurrent request cannot reserve while the orphaned permit remains.
        let mut contended = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut contended, Some("gzip")).await;
        assert!(
            !compression_response_admission_reserved_for_test(&contended),
            "orphaned buffer permit must still consume the only budget slot"
        );

        let held = take_compression_response_buffer_permit_for_test(&mut ctx);
        assert!(
            held.is_some(),
            "the buffer slot must remain with the retained body for sibling handoff \
             or request-end release"
        );
        drop(held);
        drop(ctx);

        let mut ctx2 = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx2, Some("gzip")).await;
        assert!(
            compression_response_admission_reserved_for_test(&ctx2),
            "returning the kept buffer permit must refill the pool"
        );
    })
    .await;
}

/// Narrow then broad sibling instances: the first reserves and declines, the
/// second must commit from the orphaned slot without needing a second budget
/// permit (proves no unaccounted gap between after_proxy hooks).
#[tokio::test]
async fn test_sibling_takes_orphaned_buffer_permit_after_ineligible_owner() {
    use ferrum_edge::_test_support::compression_response_admission_reserved_for_test;
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    with_test_response_buffer_budget(1, || async {
        let narrow = make_plugin(json!({
            "algorithms": ["gzip"],
            "content_types": ["text/html"],
            "min_content_length": 10
        }));
        let broad = make_plugin(json!({
            "algorithms": ["gzip"],
            "content_types": ["application/json"],
            "min_content_length": 10
        }));
        let mut ctx = make_ctx(Some("gzip"));
        let mut req_headers = HashMap::new();
        req_headers.insert("accept-encoding".to_string(), "gzip".to_string());
        assert!(matches!(
            narrow.before_proxy(&mut ctx, &mut req_headers).await,
            PluginResult::Continue
        ));
        assert!(matches!(
            broad.before_proxy(&mut ctx, &mut req_headers).await,
            PluginResult::Continue
        ));
        assert!(
            compression_response_admission_reserved_for_test(&ctx),
            "first sibling must hold the only buffer slot"
        );

        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "application/json".to_string());
        resp.insert("content-length".to_string(), "1000".to_string());
        assert!(matches!(
            narrow.after_proxy(&mut ctx, 200, &mut resp).await,
            PluginResult::Continue
        ));
        assert!(
            !resp.contains_key("content-encoding"),
            "narrow content-type whitelist must decline to commit"
        );
        assert!(
            !compression_response_admission_reserved_for_test(&ctx),
            "declining owner must clear ownership for sibling handoff"
        );

        assert!(matches!(
            broad.after_proxy(&mut ctx, 200, &mut resp).await,
            PluginResult::Continue
        ));
        assert_eq!(
            resp.get("content-encoding").map(String::as_str),
            Some("gzip"),
            "broader sibling must commit using the orphaned buffer permit \
             (budget=1 forbids a fresh acquire)"
        );
    })
    .await;
}

#[tokio::test]
async fn test_reserved_admission_released_on_bodyless_status() {
    use ferrum_edge::_test_support::compression_response_admission_reserved_for_test;
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    with_test_response_buffer_budget(1, || async {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
        assert!(compression_response_admission_reserved_for_test(&ctx));

        let mut resp = HashMap::new();
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 204, &mut resp).await,
            PluginResult::Continue
        ));
        assert!(
            !compression_response_admission_reserved_for_test(&ctx),
            "a 204 hard-skip must release the reserved response-buffer admission"
        );
        assert!(!resp.contains_key("content-encoding"));
    })
    .await;
}

#[tokio::test]
async fn test_reserved_permit_stays_on_donor_across_compat_clone() {
    use ferrum_edge::_test_support::{
        clone_for_final_request_body_hooks_for_test,
        compression_response_admission_reserved_for_test,
        take_compression_response_buffer_permit_for_test,
    };
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    with_test_response_buffer_budget(2, || async {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
        assert!(compression_response_admission_reserved_for_test(&ctx));

        // The request-body-hook compatibility clone must NOT carry the response
        // buffer permit (it never runs the response transform), otherwise the
        // permit would be released when the short-lived clone drops.
        let mut clone = clone_for_final_request_body_hooks_for_test(&mut ctx);
        assert!(
            take_compression_response_buffer_permit_for_test(&mut clone).is_none(),
            "compat clone must not carry the reserved response-buffer permit"
        );
        assert!(
            take_compression_response_buffer_permit_for_test(&mut ctx).is_some(),
            "the live context must retain the reserved response-buffer permit"
        );
    })
    .await;
}

#[tokio::test]
async fn test_cancellation_releases_reserved_permit() {
    use ferrum_edge::_test_support::compression_response_admission_reserved_for_test;
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    with_test_response_buffer_budget(1, || async {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
        assert!(compression_response_admission_reserved_for_test(&ctx));

        // Simulate a cancelled request: the context is dropped before after_proxy.
        drop(ctx);

        // The single slot is free again, so the next request can reserve it.
        let mut ctx2 = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx2, Some("gzip")).await;
        assert!(
            compression_response_admission_reserved_for_test(&ctx2),
            "dropping a reserved context must return its permit to the pool"
        );
    })
    .await;
}

#[tokio::test]
async fn test_sibling_instances_reserve_one_response_permit() {
    use ferrum_edge::plugins::compression::with_test_response_buffer_budget;

    // Two response-compressing instances must not each reserve a permit: a
    // single permit is enough for both to negotiate and one to commit.
    with_test_response_buffer_budget(1, || async {
        let plugins: Vec<Arc<dyn Plugin>> = vec![
            Arc::new(make_plugin(json!({
                "algorithms": ["gzip"],
                "min_content_length": 10
            }))),
            Arc::new(make_plugin(json!({
                "algorithms": ["gzip"],
                "min_content_length": 10
            }))),
        ];
        let mut ctx = make_ctx(Some("gzip"));
        let mut req_headers = HashMap::new();
        req_headers.insert("accept-encoding".to_string(), "gzip".to_string());
        for plugin in &plugins {
            assert!(matches!(
                plugin.before_proxy(&mut ctx, &mut req_headers).await,
                PluginResult::Continue
            ));
        }

        let mut resp = HashMap::new();
        resp.insert("content-type".to_string(), "application/json".to_string());
        resp.insert("content-length".to_string(), "1000".to_string());
        for plugin in &plugins {
            assert!(matches!(
                plugin.after_proxy(&mut ctx, 200, &mut resp).await,
                PluginResult::Continue
            ));
        }
        assert_eq!(
            resp.get("content-encoding").map(String::as_str),
            Some("gzip"),
            "one sibling commits a single coding layer from the shared reservation"
        );
    })
    .await;
}

#[tokio::test]
async fn test_request_fallback_stages_plaintext_before_header_strip() {
    use bytes::Bytes;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let plugin = make_plugin(json!({"decompress_request": true}));
    let original = b"fallback-staged-plaintext";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut ctx = make_request_ctx_with_body("gzip", &compressed);
    // Simulate the rare path: body bytes are present on the context, but
    // before_proxy has no mutable body view.
    ctx.request_body_bytes = Some(Bytes::from(compressed.clone()));
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), compressed.len().to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue), "got {result:?}");
    assert!(
        !headers.contains_key("content-encoding"),
        "successful fallback decode must strip Content-Encoding"
    );
    assert!(
        ctx.metadata.contains_key("compression:request_decoded"),
        "fallback must mark the request as decoded"
    );

    // Transform must emit staged plaintext without needing a second codec slot.
    let transformed = plugin
        .transform_request_body_with_context(&mut ctx, &compressed, None, &headers)
        .await
        .expect("staged plaintext must be transferred");
    assert_eq!(transformed.as_slice(), original);
}

#[tokio::test]
async fn test_response_encode_abort_restores_identity_representation() {
    use ferrum_edge::_test_support::{
        gateway_response_compression_algorithm_for_test,
        reconcile_aborted_gateway_response_encoding_for_test,
        take_compression_response_buffer_permit_for_test,
    };

    let plugin = make_plugin(json!({"min_content_length": 10}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    req_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp = HashMap::new();
    resp.insert("content-type".to_string(), "application/json".to_string());
    resp.insert("content-length".to_string(), "1000".to_string());
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut resp).await,
        PluginResult::Continue
    ));
    assert_eq!(
        resp.get("content-encoding").map(String::as_str),
        Some("gzip")
    );

    // Simulate a missing permit / encoder abort after Content-Encoding commit.
    let _ = take_compression_response_buffer_permit_for_test(&mut ctx);
    let mut identity = bytes::Bytes::from(compressible_json_body());
    let transformed = plugin
        .transform_response_body_with_context(&mut ctx, &identity, Some("application/json"), &resp)
        .await;
    assert!(
        transformed.is_none(),
        "encode abort must not emit compressed bytes"
    );
    let mut status = 200;
    assert!(
        !reconcile_aborted_gateway_response_encoding_for_test(
            &mut ctx,
            &mut status,
            &mut resp,
            &mut identity,
        ),
        "identity-acceptable recovery must not select a terminal rejection"
    );
    assert_eq!(status, 200);
    assert!(
        !resp.contains_key("content-encoding"),
        "encode abort must restore identity headers"
    );
    let expected_len = identity.len().to_string();
    assert_eq!(resp.get("content-length"), Some(&expected_len));
    assert!(gateway_response_compression_algorithm_for_test(&ctx).is_none());
}

/// Codec CPU admission is now acquired inside the transform, after
/// `Content-Encoding` was committed. Saturation there must abort the encode
/// (identity restored by the shared loops) and must not strand the response
/// buffer slot that admitted the body.
#[tokio::test]
async fn test_codec_saturation_at_transform_restores_identity_and_frees_buffer_slot() {
    use ferrum_edge::_test_support::{
        compression_response_admission_reserved_for_test,
        reconcile_aborted_gateway_response_encoding_for_test,
    };
    use ferrum_edge::plugins::compression::{
        with_test_codec_budget, with_test_response_buffer_budget,
    };

    // One buffer slot, zero codec permits: the reservation and the
    // Content-Encoding commit both succeed, only the CPU admission fails.
    with_test_response_buffer_budget(1, || async {
        with_test_codec_budget(0, || async {
            let plugin = make_plugin(json!({"min_content_length": 10}));
            let mut ctx = make_ctx(Some("gzip"));
            before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
            assert!(compression_response_admission_reserved_for_test(&ctx));

            let mut resp = HashMap::new();
            resp.insert("content-type".to_string(), "application/json".to_string());
            resp.insert("content-length".to_string(), "1000".to_string());
            assert!(matches!(
                plugin.after_proxy(&mut ctx, 200, &mut resp).await,
                PluginResult::Continue
            ));
            assert_eq!(
                resp.get("content-encoding").map(String::as_str),
                Some("gzip"),
                "buffer admission is what gates the commit; codec saturation is later"
            );

            let mut identity = bytes::Bytes::from(compressible_json_body());
            assert!(
                plugin
                    .transform_response_body_with_context(
                        &mut ctx,
                        &identity,
                        Some("application/json"),
                        &resp,
                    )
                    .await
                    .is_none(),
                "codec saturation must abort the encode instead of emitting bytes"
            );
            let mut status = 200;
            assert!(
                !reconcile_aborted_gateway_response_encoding_for_test(
                    &mut ctx,
                    &mut status,
                    &mut resp,
                    &mut identity,
                ),
                "identity-acceptable recovery must not select a terminal rejection"
            );
            assert_eq!(status, 200);
            assert!(
                !resp.contains_key("content-encoding"),
                "aborted encode must restore an identity representation"
            );
            assert_eq!(
                resp.get("content-length"),
                Some(&identity.len().to_string()),
                "restored identity response must carry the plaintext length"
            );

            // The single buffer slot must be reservable again: the aborted
            // transform released it rather than leaking it for the request's life.
            let mut next = make_ctx(Some("gzip"));
            before_proxy_with_accept_encoding(&plugin, &mut next, Some("gzip")).await;
            assert!(
                compression_response_admission_reserved_for_test(&next),
                "aborted encode must not strand the response-buffer permit"
            );
        })
        .await;
    })
    .await;
}

/// A codec slot can disappear after `Content-Encoding` is committed. If the
/// client explicitly refused identity, recovery must fail closed with 406
/// rather than emit the plaintext representation the client excluded.
#[tokio::test]
async fn test_codec_saturation_with_identity_forbidden_returns_406() {
    use ferrum_edge::_test_support::reconcile_aborted_gateway_response_encoding_for_test;
    use ferrum_edge::plugins::compression::{
        with_test_codec_budget, with_test_response_buffer_budget,
    };

    with_test_response_buffer_budget(1, || async {
        with_test_codec_budget(0, || async {
            let plugin = make_plugin(json!({"min_content_length": 10}));
            let mut ctx = make_ctx(Some("gzip, identity;q=0"));
            before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip, identity;q=0")).await;

            let mut resp = HashMap::new();
            resp.insert("content-type".to_string(), "application/json".to_string());
            resp.insert("content-length".to_string(), "1000".to_string());
            assert!(matches!(
                plugin.after_proxy(&mut ctx, 200, &mut resp).await,
                PluginResult::Continue
            ));

            let mut body = bytes::Bytes::from(compressible_json_body());
            assert!(
                plugin
                    .transform_response_body_with_context(
                        &mut ctx,
                        &body,
                        Some("application/json"),
                        &resp,
                    )
                    .await
                    .is_none()
            );
            let mut status = 200;
            assert!(reconcile_aborted_gateway_response_encoding_for_test(
                &mut ctx,
                &mut status,
                &mut resp,
                &mut body,
            ));
            assert_eq!(status, 406);
            assert_eq!(
                resp.get("content-type").map(String::as_str),
                Some("application/json")
            );
            assert_eq!(
                resp.get("vary").map(String::as_str),
                Some("Accept-Encoding")
            );
            assert!(!resp.contains_key("content-encoding"));
            assert_eq!(resp.get("content-length"), Some(&body.len().to_string()));
            assert!(
                String::from_utf8(body.to_vec())
                    .expect("406 body must be UTF-8")
                    .contains("not acceptable")
            );
        })
        .await;
    })
    .await;
}

/// A completed encode releases the buffer slot, so the next request recovers
/// the admission. The permit is held across the encode itself so the retained
/// body population never exceeds the buffer budget.
#[tokio::test]
async fn test_buffer_slot_recovers_after_successful_encode() {
    use ferrum_edge::_test_support::compression_response_admission_reserved_for_test;
    use ferrum_edge::plugins::compression::{
        with_test_codec_budget, with_test_response_buffer_budget,
    };

    with_test_response_buffer_budget(1, || async {
        with_test_codec_budget(1, || async {
            let plugin = make_plugin(json!({"min_content_length": 10}));
            let mut ctx = make_ctx(Some("gzip"));
            before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;

            let identity = compressible_json_body();
            let mut resp = HashMap::new();
            resp.insert("content-type".to_string(), "application/json".to_string());
            resp.insert("content-length".to_string(), identity.len().to_string());
            assert!(matches!(
                plugin.after_proxy(&mut ctx, 200, &mut resp).await,
                PluginResult::Continue
            ));

            // While the reservation is outstanding the only slot is taken, so a
            // concurrent request must be declined onto the identity/stream path.
            let mut contended = make_ctx(Some("gzip"));
            before_proxy_with_accept_encoding(&plugin, &mut contended, Some("gzip")).await;
            assert!(
                !compression_response_admission_reserved_for_test(&contended),
                "an outstanding reservation must consume the only buffer slot"
            );

            let compressed = plugin
                .transform_response_body_with_context(
                    &mut ctx,
                    &identity,
                    Some("application/json"),
                    &resp,
                )
                .await
                .expect("codec admission is available, so the encode must succeed");
            assert!(!compressed.is_empty());
            assert_ne!(compressed, identity, "body must actually be gzip encoded");

            let mut next = make_ctx(Some("gzip"));
            before_proxy_with_accept_encoding(&plugin, &mut next, Some("gzip")).await;
            assert!(
                compression_response_admission_reserved_for_test(&next),
                "a completed encode must return the buffer slot to the budget"
            );
        })
        .await;
    })
    .await;
}

/// Response-buffer saturation is a distinct, scrapeable outcome from codec
/// saturation so operators can tell a memory-admission refusal from a CPU one.
#[tokio::test]
async fn test_response_buffer_saturation_is_metered_separately() {
    use ferrum_edge::plugins::compression::{
        compression_codec_metrics, with_test_response_buffer_budget,
    };

    let before = compression_codec_metrics();
    with_test_response_buffer_budget(0, || async {
        let plugin = make_plugin(json!({}));
        let mut ctx = make_ctx(Some("gzip"));
        before_proxy_with_accept_encoding(&plugin, &mut ctx, Some("gzip")).await;
    })
    .await;
    let after = compression_codec_metrics();
    // Counters are process-global and other tests run in parallel, so assert a
    // monotonic delta rather than an exact value.
    assert!(
        after.response_buffer_saturated > before.response_buffer_saturated,
        "a refused reservation must increment ferrum_compression_response_buffer_saturated_total"
    );
}

#[test]
fn test_response_buffer_budget_constant_is_independent_of_codec_budget() {
    use ferrum_edge::plugins::compression::{
        MAX_CONCURRENT_CODEC_JOBS, MAX_CONCURRENT_RESPONSE_BUFFERS,
    };

    // Values match today by design, but each semaphore must be sized from its
    // own named constant so resizing codec CPU concurrency cannot silently
    // resize retained-body admission (or the reverse).
    assert_eq!(MAX_CONCURRENT_CODEC_JOBS, 32);
    assert_eq!(MAX_CONCURRENT_RESPONSE_BUFFERS, 32);
    let src = include_str!("../../../src/plugins/compression.rs");
    assert!(
        src.contains("Semaphore::new(MAX_CONCURRENT_CODEC_JOBS)"),
        "codec CPU semaphore must be sized from MAX_CONCURRENT_CODEC_JOBS"
    );
    assert!(
        src.contains("Semaphore::new(MAX_CONCURRENT_RESPONSE_BUFFERS)"),
        "response-buffer semaphore must be sized from MAX_CONCURRENT_RESPONSE_BUFFERS"
    );
    // Pin the response-buffer LazyLock initializer to the buffer constant so a
    // future edit cannot quietly retarget it at MAX_CONCURRENT_CODEC_JOBS.
    let budget_idx = src
        .find("static RESPONSE_BUFFER_BUDGET")
        .expect("RESPONSE_BUFFER_BUDGET must exist");
    let budget_window = &src[budget_idx..budget_idx.saturating_add(220).min(src.len())];
    assert!(
        budget_window.contains("MAX_CONCURRENT_RESPONSE_BUFFERS"),
        "RESPONSE_BUFFER_BUDGET initializer must reference MAX_CONCURRENT_RESPONSE_BUFFERS"
    );
    assert!(
        !budget_window.contains("MAX_CONCURRENT_CODEC_JOBS"),
        "RESPONSE_BUFFER_BUDGET must not be sized from the codec concurrency constant"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_codec_offload_allows_unrelated_async_progress() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    let plugin = make_plugin(json!({"min_content_length": 10, "gzip_level": 9}));
    let body = vec![b'a'; 64 * 1024];
    let progressed = Arc::new(AtomicBool::new(false));
    let progressed_flag = Arc::clone(&progressed);

    let mut ctx = make_ctx(Some("gzip"));
    let mut req_headers = HashMap::new();
    req_headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugin.before_proxy(&mut ctx, &mut req_headers).await;
    let mut resp = HashMap::new();
    resp.insert("content-type".to_string(), "application/json".to_string());
    resp.insert("content-length".to_string(), body.len().to_string());
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut resp).await,
        PluginResult::Continue
    ));

    let encode = tokio::spawn(async move {
        plugin
            .transform_response_body_with_context(&mut ctx, &body, Some("application/json"), &resp)
            .await
    });

    // Deterministic liveness: an unrelated task must be able to run while the
    // codec job occupies a blocking-pool worker. No wall-clock threshold.
    let observer = tokio::spawn(async move {
        progressed_flag.store(true, AtomicOrdering::SeqCst);
    });

    while !progressed.load(AtomicOrdering::SeqCst) && !encode.is_finished() {
        tokio::task::yield_now().await;
    }
    assert!(
        progressed.load(AtomicOrdering::SeqCst),
        "Tokio must schedule unrelated work while bounded codec jobs run on spawn_blocking"
    );
    observer.await.expect("observer task");
    let compressed = encode
        .await
        .expect("encode task join")
        .expect("encode must succeed under an unsaturated budget");
    assert!(
        !compressed.is_empty(),
        "compressed output should be non-empty"
    );
}

#[test]
fn test_validation_and_admin_paths_apply_process_compression_admission_policy() {
    // Every plugin-construction/admission client that does not inherit a live
    // ProxyState must apply the process body-limit + codec-gate cross-check.
    let plugins_mod = include_str!("../../../src/plugins/mod.rs");
    let admin = include_str!("../../../src/admin/mod.rs");
    let pipeline = include_str!("../../../src/config/validation_pipeline.rs");
    let http_client = include_str!("../../../src/plugins/utils/http_client.rs");
    assert!(
        http_client.contains("fn with_process_compression_admission_policy"),
        "PluginHttpClient must expose the shared admission-policy seam"
    );
    assert!(
        plugins_mod.contains("with_process_compression_admission_policy()"),
        "validate_plugin_config* must apply process compression admission policy"
    );
    assert!(
        admin.contains("with_process_compression_admission_policy()"),
        "admin plugin_validation_http_client fallback must apply process policy"
    );
    assert!(
        pipeline.contains("with_process_compression_admission_policy()"),
        "config validation pipeline must apply process compression admission policy"
    );
}

#[test]
fn test_shared_paths_reconcile_aborted_gateway_encoding() {
    // Pin that every shared buffered response-body transform loop restores
    // identity when compression marks an encode abort.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let h3 = include_str!("../../../src/http3/cross_protocol.rs");
    assert!(
        proxy
            .matches("reconcile_aborted_gateway_response_encoding")
            .count()
            >= 2,
        "H1/H2 shared transform helpers must reconcile aborted gateway encodings"
    );
    assert!(
        h3.matches("reconcile_aborted_gateway_response_encoding")
            .count()
            >= 2,
        "H3 cross-protocol buffered transforms must reconcile aborted gateway encodings"
    );
}
