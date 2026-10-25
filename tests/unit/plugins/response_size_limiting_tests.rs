//! Tests for response_size_limiting plugin

use bytes::Bytes;
use ferrum_edge::_test_support::finalize_synthetic_response_for_test;
use ferrum_edge::plugins::response_size_limiting::ResponseSizeLimiting;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, validate_plugin_config};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_ctx() -> RequestContext {
    make_ctx_with_method("GET")
}

fn make_ctx_with_method(method: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/api".to_string(),
    )
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "response_size_limiting");
    assert_eq!(plugin.priority(), 3490);
}

#[tokio::test]
async fn test_zero_max_bytes_returns_error() {
    let result = ResponseSizeLimiting::new(&json!({}));
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(err.contains("max_bytes"));
}

#[tokio::test]
async fn test_non_object_config_returns_error() {
    let result = ResponseSizeLimiting::new(&json!("bad"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[tokio::test]
async fn test_invalid_require_buffered_check_type_returns_error() {
    let result = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_check": "yes"
    }));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("require_buffered_check"));
}

#[test]
fn test_unknown_config_keys_rejected_with_spelling_suggestion() {
    let err = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_checks": true
    }))
    .err()
    .expect("misspelled strict-check key must be rejected");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(err.contains("require_buffered_checks"), "{err}");
    assert!(
        err.contains("did you mean `require_buffered_check`?"),
        "{err}"
    );

    let shared = validate_plugin_config(
        "response_size_limiting",
        &json!({
            "max_bytes": 1024,
            "require_buffered_checks": true
        }),
    )
    .expect_err("shared admission must reject the same typo");
    assert!(shared.contains("require_buffered_checks"), "{shared}");
}

#[test]
fn test_explicit_null_require_buffered_check_rejected() {
    let err = ResponseSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "require_buffered_check": null
    }))
    .err()
    .expect("explicit null must be rejected");
    assert!(
        err.contains("`require_buffered_check` must be a boolean"),
        "{err}"
    );
    assert!(
        !err.contains("unknown configuration key"),
        "recognized-field null must not be mislabeled as unknown: {err}"
    );
}

#[test]
fn test_omitted_require_buffered_check_defaults_false() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024}))
        .expect("omitted strict-check flag must keep default");
    assert!(!plugin.requires_response_body_buffering());
}

// === Content-Length fast path (after_proxy) ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "512".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1025".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Response body too large"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_content_length_header_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_fails_closed() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "bad".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("Expected 502 Reject, got {other:?}"),
    }
}

// === Bodyless response semantics (issue #2343) ===
// after_proxy is the shared H1/H2/H3 Content-Length fast path; method/status
// coverage here applies to every HTTP-family protocol path.

#[tokio::test]
async fn test_oversized_content_length_on_head_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx_with_method("HEAD");
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string());

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "HEAD may advertise representation Content-Length without a body"
    );
}

#[tokio::test]
async fn test_oversized_content_length_on_304_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string());

    let result = plugin.after_proxy(&mut ctx, 304, &mut headers).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "304 may carry representation Content-Length with no message body"
    );
}

#[tokio::test]
async fn test_oversized_content_length_on_206_still_rejects() {
    // Body-bearing control: partial content still transfers body bytes.
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string());

    match plugin.after_proxy(&mut ctx, 206, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject for oversized body-bearing 206"),
    }
}

#[tokio::test]
async fn test_body_bearing_exact_boundary_still_passes_for_206() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024".to_string());

    let result = plugin.after_proxy(&mut ctx, 206, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Final body check (on_final_response_body) ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 100, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"short";

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 10, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"this response body is definitely longer than ten bytes";

    match plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await
    {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Response body too large"));
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_buffered_body_at_limit_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 5})).unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();
    let body = b"12345";

    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, body)
        .await;
    assert!(matches!(result, PluginResult::Continue));
}

// === Response body buffering flag ===

#[tokio::test]
async fn test_requires_buffering_when_configured() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert!(plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_no_buffering_by_default() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_max_bytes_zero_returns_error() {
    let result =
        ResponseSizeLimiting::new(&json!({"max_bytes": 0, "require_buffered_check": true}));
    assert!(result.is_err());
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === Rejection body format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "100".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "Response body too large");
            assert_eq!(parsed["limit"], 10);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Large response ===

#[tokio::test]
async fn test_large_content_length_rejects() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1048576})).unwrap(); // 1 MiB
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "10485760".to_string()); // 10 MiB

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject"),
    }
}

// === SSE policy boundary ===

#[tokio::test]
async fn test_sse_request_intent_cannot_skip_strict_response_limit() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert!(plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
    let response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &response_headers,
    ));
    assert!(plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new(),));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; profile=event-stream"),
        200,
        &HashMap::new(),
    ));
}

#[tokio::test]
async fn test_non_sse_request_still_buffers() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "application/json".to_string());

    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_buffering_disabled_stays_disabled_for_sse() {
    // When require_buffered_check is off the buffer flag is false; SSE
    // detection must not flip it on.
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_response_body_buffering());

    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    assert!(!plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn test_sse_content_length_fast_path_still_runs() {
    // Backends that advertise a Content-Length larger than the limit retain
    // the ordinary fast-path rejection before the SSE-specific boundary.
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "2048".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 502);
        }
        _ => panic!("Expected Reject when Content-Length exceeds limit"),
    }
}

#[tokio::test]
async fn test_genuine_sse_fails_closed_at_strict_route_limit() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    let mut ctx = make_ctx();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Streaming response size cannot be verified"));
            assert!(body.contains("1024"));
        }
        _ => panic!("Expected fail-closed event-stream rejection"),
    }
}

/// Keep `docs/size_limits.md` aligned with the streaming runtime contract that
/// `response_size_limiting` points operators at (issue #2346). Unknown-length
/// responses must not be documented as a full-buffer fallback that promises a
/// post-commit JSON 502.
#[test]
fn test_size_limits_guide_matches_streaming_runtime_contract() {
    let size_limits = include_str!("../../../docs/size_limits.md");
    let streaming = include_str!("../../../docs/response_body_streaming.md");
    let plugin_docs = include_str!("../../../docs/plugins.md");

    assert!(
        !size_limits.contains("falls back to buffering"),
        "size_limits.md must not claim unknown-length responses fall back to buffering"
    );
    assert!(
        size_limits.contains("SizeLimitedStreamingResponse"),
        "size_limits.md must name SizeLimitedStreamingResponse for unknown-length streaming"
    );
    assert!(
        size_limits.contains("post-commit"),
        "size_limits.md must distinguish post-commit stream termination from pre-commit rejection"
    );
    assert!(
        size_limits.contains("response_body_streaming.md#interaction-with-response-size-limits"),
        "size_limits.md must link the streaming size-limit section"
    );
    assert!(
        size_limits.contains("plugins.md#response_size_limiting"),
        "size_limits.md must link the response_size_limiting plugin reference"
    );

    // Counterpart docs already describe the streaming adapter; keep the shared
    // terminology from drifting back to a buffering-only story.
    assert!(streaming.contains("SizeLimitedStreamingResponse"));
    assert!(
        plugin_docs.contains("SizeLimitedStreamingResponse"),
        "response_size_limiting reference must mention the global streaming adapter"
    );
}

// === Route ceiling publication (GHSA-xrfj-852f-645j) ===

/// Publication is deliberately independent of `require_buffered_check`. It gives
/// the core two things the hooks cannot express: buffered collection aborts at
/// this ceiling instead of retaining up to the larger global allowance, and an
/// already-buffered synthetic body is governed without another plugin having to
/// activate the response body-hook gate.
#[test]
fn enforced_response_body_limit_is_published_without_forcing_buffering() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.enforced_response_body_limit(), Some(1024));
    // The default instance advertises no buffering — that was exactly why the
    // synthetic body-hook gate stayed closed before the fix.
    assert!(!plugin.requires_response_body_buffering());
    // It is a response-side policy only.
    assert_eq!(plugin.enforced_request_body_limit(), None);
}

#[test]
fn strict_instance_publishes_the_same_ceiling_and_forces_buffering() {
    let plugin =
        ResponseSizeLimiting::new(&json!({"max_bytes": 1024, "require_buffered_check": true}))
            .unwrap();
    assert_eq!(plugin.enforced_response_body_limit(), Some(1024));
    assert!(plugin.requires_response_body_buffering());
}

// === Already-buffered synthetic response enforcement ===

#[tokio::test]
async fn synthetic_response_uses_strictest_global_and_route_ceiling() {
    for (global_limit, route_limit, body, expected_status) in [
        // A looser route policy cannot relax the global ceiling.
        (4usize, Some(10u64), b"12345".as_slice(), 502u16),
        // An unlimited global cannot disable the route ceiling.
        (0usize, Some(4u64), b"12345".as_slice(), 502u16),
        // The exact effective boundary is permitted.
        (4usize, Some(10u64), b"1234".as_slice(), 200u16),
    ] {
        let plugin_limit = route_limit.unwrap_or(10);
        let plugin: Arc<dyn Plugin> =
            Arc::new(ResponseSizeLimiting::new(&json!({"max_bytes": plugin_limit})).unwrap());
        let plugins = vec![plugin];
        let mut ctx = make_ctx();
        ctx.max_response_body_size_bytes = global_limit;
        ctx.route_response_body_limit_bytes = route_limit;
        let mut status = 200;
        let mut headers = HashMap::new();
        let mut response_body = Bytes::copy_from_slice(body);

        finalize_synthetic_response_for_test(
            &plugins,
            &mut ctx,
            &mut status,
            &mut headers,
            &mut response_body,
        )
        .await;

        assert_eq!(
            status,
            expected_status,
            "global={global_limit}, route={route_limit:?}, body_len={}",
            body.len()
        );
    }
}

#[tokio::test]
async fn synthetic_response_without_route_plugin_still_honors_global_ceiling() {
    let mut ctx = make_ctx();
    ctx.max_response_body_size_bytes = 4;
    ctx.route_response_body_limit_bytes = None;
    let mut status = 200;
    let mut headers = HashMap::new();
    let mut response_body = Bytes::from_static(b"12345");

    finalize_synthetic_response_for_test(
        &[],
        &mut ctx,
        &mut status,
        &mut headers,
        &mut response_body,
    )
    .await;

    assert_eq!(status, 502);
    assert!(
        String::from_utf8_lossy(&response_body).contains("Response body too large"),
        "global-only rejection must replace the synthetic body"
    );
}

// === Repeated / ambiguous response Content-Length (GHSA-xrfj-852f-645j) ===

/// Hyper accepts a backend response whose `Content-Length` repeats with
/// identical values, and the shared collector folds those repeats with `", "`.
/// Parsing the whole folded list as one integer used to fail, so the fast path
/// missed an oversized coalesced declaration.
#[tokio::test]
async fn test_repeated_identical_response_content_length_rejects_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "2048, 2048".to_string());

    match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("Expected 502 Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_repeated_identical_response_content_length_at_boundary_passes() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("content-length".to_string(), "1024, 1024".to_string());

    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));
}

/// A response declared length that cannot be reduced to one value fails closed.
#[tokio::test]
async fn test_ambiguous_response_content_length_fails_closed_with_502() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    for value in ["2048, 4096", "+2048"] {
        let mut ctx = make_ctx();
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), value.to_string());

        match plugin.after_proxy(&mut ctx, 200, &mut headers).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 502, "{value:?} must fail closed");
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(parsed["error"], "Response Content-Length is ambiguous");
            }
            other => panic!("Expected 502 Reject for {value:?}, got {other:?}"),
        }
    }
}

/// Bodyless semantics are unaffected: their `Content-Length` describes a
/// representation, not transferred bytes, so neither an oversized value nor an
/// ambiguous fold is a body-size violation.
#[tokio::test]
async fn test_bodyless_responses_ignore_repeated_and_ambiguous_lengths() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    for (method, status, value) in [
        ("HEAD", 200u16, "2048, 2048"),
        ("GET", 304, "2048, 2048"),
        ("GET", 204, "2048, 4096"),
        ("HEAD", 200, "2048, 4096"),
    ] {
        let mut ctx = make_ctx_with_method(method);
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), value.to_string());

        assert!(
            matches!(
                plugin.after_proxy(&mut ctx, status, &mut headers).await,
                PluginResult::Continue
            ),
            "bodyless {method} {status} with {value:?} must not trip a body-size limit"
        );
    }
}

/// A chunked / unknown-length response has no declared length: the fast path
/// stays quiet and the bounded collector enforces the ceiling.
#[tokio::test]
async fn test_unknown_length_response_passes_the_header_fast_path() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();

    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut headers).await,
        PluginResult::Continue
    ));
}

/// Post-transform enforcement is preserved: a body that expands past the ceiling
/// after response transforms is still refused.
#[tokio::test]
async fn test_final_response_body_over_limit_still_rejects_after_transforms() {
    let plugin = ResponseSizeLimiting::new(&json!({"max_bytes": 8})).unwrap();
    let mut ctx = make_ctx();
    let headers = HashMap::new();

    assert!(matches!(
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, b"12345678")
            .await,
        PluginResult::Continue
    ));
    match plugin
        .on_final_response_body(&mut ctx, 200, &headers, b"123456789")
        .await
    {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("Expected 502 Reject, got {other:?}"),
    }
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [
        (
            json!({"max_bytes": false}),
            "`max_bytes`",
            "must be an integer, not a boolean",
        ),
        (
            json!({"max_bytes": 1, "require_buffered_check": 918273641}),
            "`require_buffered_check`",
            "must be a boolean",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("response_size_limiting", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}
