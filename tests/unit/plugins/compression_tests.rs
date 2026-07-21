use ferrum_edge::plugins::compression::{COMPRESSION_CONFIG_KEYS, CompressionPlugin};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, validate_plugin_config};
use serde_json::json;
use std::collections::HashMap;

fn make_plugin(config: serde_json::Value) -> CompressionPlugin {
    CompressionPlugin::new(&config).unwrap()
}

fn make_ctx(accept_encoding: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
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
fn test_applies_after_proxy_on_reject() {
    let plugin = make_plugin(json!({}));
    assert!(plugin.applies_after_proxy_on_reject());
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
async fn test_wildcard_quality_applies_to_unlisted_algorithms_and_identity() {
    // `*;q=0.3` assigns q=0.3 to unlisted gzip/br; identity;q=0 refuses the
    // uncoded representation. The wildcard algorithm is the only acceptable
    // representation, so the gateway compresses with its preferred algorithm.
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
async fn test_406_not_applied_to_compression_ineligible_response() {
    // The negotiation failure only applies when the response is eligible for
    // gateway compression. A non-whitelisted content type cannot be recoded
    // by Ferrum at all, so it is forwarded as the only available (identity)
    // representation rather than replaced by a gateway negotiation error.
    let plugin = make_plugin(json!({}));
    let mut ctx = make_ctx(Some("*;q=0"));
    let mut headers = HashMap::new();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "image/png".to_string());
    resp_headers.insert("content-length".to_string(), "1000".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
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
}

// ────────────────────── Vary header ──────────────────────

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

// ────────────────────── before_proxy: request decompression header cleanup ─

#[tokio::test]
async fn test_before_proxy_strips_content_encoding_for_decompression() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(Some("gzip"));
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), "42".to_string());

    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
    assert_eq!(
        ctx.metadata.get("compression:request_encoding").unwrap(),
        "gzip"
    );
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

/// #87: a present-but-unparseable q-value (`gzip;q=abc`) is treated as not
/// acceptable (q=0), so gzip must NOT be selected when it is the only codec.
#[tokio::test]
async fn test_malformed_q_value_treated_as_not_acceptable() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=abc").await;
    assert_eq!(
        selected, None,
        "a garbage q-value must be treated as q=0 (not acceptable), not q=1.0"
    );
}

/// #87: an empty q-value (`gzip;q=`) is likewise not acceptable.
#[tokio::test]
async fn test_empty_q_value_treated_as_not_acceptable() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=").await;
    assert_eq!(selected, None);
}

/// #87: a malformed q on one codec must not let it beat a well-formed,
/// genuinely-preferred codec. `gzip;q=abc` (→ q=0) loses to `br;q=1`.
#[tokio::test]
async fn test_malformed_q_value_does_not_outrank_valid_codec() {
    // Server preference is gzip-first; without the fix gzip;q=abc would parse as
    // q=1.0 and win the tie. With the fix it is q=0 and excluded, so br wins.
    let selected = negotiate_encoding(json!(["gzip", "br"]), "gzip;q=abc, br;q=1").await;
    assert_eq!(selected.as_deref(), Some("br"));
}

/// #87: `q=NaN` parses to a float in Rust but must be rejected as non-finite
/// (q=0) so it neither wins selection nor poisons the highest-q tie-break math.
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

/// #87: a q-value above 1.0 is clamped to 1.0 (still acceptable) rather than
/// rejected — clamping must not turn a valid (if out-of-range) weight into a
/// refusal.
#[tokio::test]
async fn test_out_of_range_q_value_is_clamped_not_refused() {
    let selected = negotiate_encoding(json!(["gzip"]), "gzip;q=5").await;
    assert_eq!(selected.as_deref(), Some("gzip"));
}

// ──────────────── #60: multi-member gzip request decompression ────────────────

/// #60: a concatenated multi-member gzip request body must be decoded in full.
/// `GzDecoder` would stop after the first member and silently truncate the body;
/// `MultiGzDecoder` decodes every member.
#[tokio::test]
async fn test_multi_member_gzip_request_decompression() {
    use flate2::write::GzEncoder;
    use std::io::Write;

    let part_a = b"first gzip member payload; ";
    let part_b = b"second gzip member payload!";

    // Build two independent gzip members and concatenate them — a valid
    // multi-member stream per RFC 1952 §2.2.
    let mut compressed = Vec::new();
    for part in [part_a.as_slice(), part_b.as_slice()] {
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(part).unwrap();
        compressed.extend_from_slice(&encoder.finish().unwrap());
    }

    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());

    let decompressed = plugin
        .transform_request_body(&compressed, Some("application/octet-stream"), &headers)
        .await
        .expect("multi-member gzip should decompress");

    let mut expected = Vec::new();
    expected.extend_from_slice(part_a);
    expected.extend_from_slice(part_b);
    assert_eq!(
        decompressed, expected,
        "both gzip members must be decoded; the body must not be truncated to the first member"
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
/// cannot validate, so it falls back to the prior behaviour: continue and strip
/// headers (no spurious reject).
#[tokio::test]
async fn test_before_proxy_without_buffered_body_falls_back_to_strip() {
    let plugin = make_plugin(json!({"decompress_request": true}));
    let mut ctx = make_ctx(None); // no request_body_bytes set
    let mut headers = HashMap::new();
    headers.insert("content-encoding".to_string(), "gzip".to_string());
    headers.insert("content-length".to_string(), "42".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("content-encoding"));
    assert!(!headers.contains_key("content-length"));
}
