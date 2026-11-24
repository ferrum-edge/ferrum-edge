//! Tests for request_size_limiting plugin

use ferrum_edge::plugins::request_size_limiting::{
    AMBIGUOUS_CONTENT_LENGTH_BODY, REJECTION_INSTANCE_METADATA_KEY, REJECTION_LIMIT_METADATA_KEY,
    REJECTION_OBSERVED_METADATA_KEY, REJECTION_REASON_METADATA_KEY, RequestSizeLimiting,
};
use ferrum_edge::plugins::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, RequestContext, priority};
use ferrum_edge::util::body_limit::REQUEST_BODY_TOO_LARGE_BODY;
use serde_json::json;
use std::collections::HashMap;

fn make_ctx(method: &str, path: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        path.to_string(),
    )
}

// === Plugin creation ===

#[tokio::test]
async fn test_creation_defaults() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "request_size_limiting");
    assert_eq!(plugin.priority(), priority::REQUEST_SIZE_LIMITING);
    assert_eq!(plugin.supported_protocols(), HTTP_GRPC_PROTOCOLS);
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
}

#[tokio::test]
async fn test_zero_max_bytes_returns_error() {
    // Empty config defaults max_bytes to 0, which is now rejected at construction time
    let result = RequestSizeLimiting::new(&json!({}));
    assert!(
        result.is_err(),
        "Expected error when max_bytes is zero/missing"
    );
}

#[test]
fn test_non_object_config_returns_error() {
    let result = RequestSizeLimiting::new(&json!("bad"));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_invalid_max_bytes_type_returns_error() {
    let result = RequestSizeLimiting::new(&json!({"max_bytes": "1024"}));
    assert!(result.is_err());
    assert!(result.err().unwrap().contains("max_bytes"));
}

#[test]
fn test_unknown_config_key_max_bytez_is_rejected() {
    let err = RequestSizeLimiting::new(&json!({
        "max_bytes": 1024,
        "max_bytez": 2048
    }))
    .err()
    .expect("typo max_bytez must be rejected");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(err.contains("max_bytez"), "{err}");
    assert!(err.contains("did you mean `max_bytes`?"), "{err}");
}

// === Content-Length fast path ===

#[tokio::test]
async fn test_content_length_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "512".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_at_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1024".to_string());

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_content_length_over_limit_rejects_413() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1025".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert_eq!(body, REQUEST_BODY_TOO_LARGE_BODY);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_content_length_header_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    // No content-length header

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_invalid_content_length_header_fails_closed() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "not-a-number".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 400),
        other => panic!("Expected 400 Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_large_content_length_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1048576})).unwrap(); // 1 MiB
    let mut ctx = make_ctx("PUT", "/upload");
    ctx.headers
        .insert("content-length".to_string(), "10485760".to_string()); // 10 MiB

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Buffered body check in before_proxy ===

#[tokio::test]
async fn test_buffered_body_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 100})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body".to_string(), "short body".to_string());

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_buffered_body_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata.insert(
        "request_body".to_string(),
        "this body is definitely longer than 10 bytes".to_string(),
    );

    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert_eq!(body, REQUEST_BODY_TOO_LARGE_BODY);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_buffered_binary_body_size_metadata_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "11".to_string());

    let mut headers = HashMap::new();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

#[tokio::test]
async fn test_no_buffered_body_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    // No request_body in metadata

    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_under_limit_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let headers = HashMap::new();

    let result = plugin.on_final_request_body(&headers, b"1234567890").await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_final_request_body_over_limit_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let headers = HashMap::new();

    match plugin.on_final_request_body(&headers, b"12345678901").await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 413);
            assert_eq!(body, REQUEST_BODY_TOO_LARGE_BODY);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Protocol support ===

#[tokio::test]
async fn test_supports_http_and_grpc() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Http));
    assert!(protocols.contains(&ferrum_edge::plugins::ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ferrum_edge::plugins::ProxyProtocol::WebSocket));
}

// === GET requests with Content-Length (unusual but valid) ===

#[tokio::test]
async fn test_get_request_with_oversized_content_length_rejects() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 100})).unwrap();
    let mut ctx = make_ctx("GET", "/api");
    ctx.headers
        .insert("content-length".to_string(), "200".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => {
            assert_eq!(status_code, 413);
        }
        _ => panic!("Expected Reject"),
    }
}

// === Response body JSON format ===

#[tokio::test]
async fn test_rejection_body_is_valid_json() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "100".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { body, .. } => {
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["error"], "Request body exceeds maximum size");
            // The limit goes to request metadata, not the client-facing body.
            assert!(parsed.get("limit").is_none(), "{body}");
        }
        _ => panic!("Expected Reject"),
    }
}

// === Route ceiling publication (GHSA-xrfj-852f-645j) ===

/// The plugin must publish its ceiling to the proxy core, otherwise an
/// unbuffered H1/H2, H3, or streaming-gRPC upload is only bounded by the
/// generally larger global limit — and by nothing at all when the global limit
/// is disabled. The hooks below can only see a declared `Content-Length` or a
/// body some *other* plugin happened to buffer.
#[test]
fn enforced_request_body_limit_publishes_the_configured_ceiling() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert_eq!(plugin.enforced_request_body_limit(), Some(1024));
    // It is a request-side policy only.
    assert_eq!(plugin.enforced_response_body_limit(), None);
}

/// Publication must not silently force body buffering: the ceiling is enforced
/// by the streaming adapters, so a streaming upload stays streaming.
#[test]
fn publishing_a_ceiling_does_not_force_request_body_buffering() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    assert!(!plugin.requires_request_body_buffering());
}

// === Repeated / ambiguous Content-Length (GHSA-xrfj-852f-645j) ===

/// A standards-valid repeated identical `Content-Length` arrives comma-folded in
/// the plugin-facing header map. Parsing the whole folded list as one integer
/// used to fail, which read as "no declared length" and skipped this reject.
#[tokio::test]
async fn test_repeated_identical_content_length_over_limit_rejects_413() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "2048, 2048".to_string());

    match plugin.on_request_received(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 413),
        other => panic!("Expected 413 Reject, got {other:?}"),
    }
}

/// Exact boundary still passes when every folded member agrees.
#[tokio::test]
async fn test_repeated_identical_content_length_at_boundary_passes() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1024, 1024".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

/// A declared length the gateway cannot reduce to one value fails closed: it is
/// refused as a bad request rather than forwarded as "unknown length".
#[tokio::test]
async fn test_ambiguous_content_length_fails_closed_with_400() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    for value in ["2048, 4096", "+2048", "2048,,2048"] {
        let mut ctx = make_ctx("POST", "/api");
        ctx.headers
            .insert("content-length".to_string(), value.to_string());

        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 400, "{value:?} must fail closed");
                assert_eq!(body, AMBIGUOUS_CONTENT_LENGTH_BODY);
                let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
                assert_eq!(parsed["error"], "Request Content-Length is ambiguous");
            }
            other => panic!("Expected 400 Reject for {value:?}, got {other:?}"),
        }
    }
}

/// A chunked / unknown-length upload has no declared length: the fast path must
/// stay quiet and leave enforcement to the streaming adapter.
#[tokio::test]
async fn test_unknown_length_request_passes_the_header_fast_path() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("transfer-encoding".to_string(), "chunked".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
}

/// Post-transform enforcement is preserved: a body that expands past the
/// ceiling after request transforms is still refused.
#[tokio::test]
async fn test_final_request_body_over_limit_still_rejects_after_transforms() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 8})).unwrap();
    let headers = HashMap::new();

    assert!(matches!(
        plugin.on_final_request_body(&headers, b"12345678").await,
        PluginResult::Continue
    ));
    match plugin.on_final_request_body(&headers, b"123456789").await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 413),
        other => panic!("Expected 413 Reject, got {other:?}"),
    }
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [(
        json!({"max_bytes": true}),
        "`max_bytes`",
        "must be an integer, not a boolean",
    )] {
        let error = ferrum_edge::plugins::validate_plugin_config("request_size_limiting", &config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// === Configuration diagnostics name the actual fault ===

/// A wrong-type `max_bytes` used to be reported as "must be greater than zero",
/// sending an operator who wrote `"1048576"` or `1048576.0` to debug the wrong
/// thing. Each fault class now has its own value-free reason.
#[test]
fn config_errors_name_the_actual_fault_class() {
    for (config, reason) in [
        (json!({}), "`max_bytes` is required"),
        (json!({"max_bytes": null}), "`max_bytes` is required"),
        (
            json!({"max_bytes": 0}),
            "`max_bytes` must be greater than zero",
        ),
        (json!({"max_bytes": -1}), "`max_bytes` must not be negative"),
        (
            json!({"max_bytes": 1.5}),
            "`max_bytes` must be written as an integer",
        ),
        (
            json!({"max_bytes": 1048576.0}),
            "`max_bytes` must be written as an integer",
        ),
        (
            json!({"max_bytes": "1048576"}),
            "`max_bytes` must be an integer, not a string",
        ),
        (
            json!({"max_bytes": false}),
            "`max_bytes` must be an integer, not a boolean",
        ),
        (
            json!({"max_bytes": [1024]}),
            "`max_bytes` must be an integer, not an array",
        ),
        (
            json!({"max_bytes": {"bytes": 1024}}),
            "`max_bytes` must be an integer, not an object",
        ),
    ] {
        let error = match RequestSizeLimiting::new(&config) {
            Ok(_) => panic!("{config} must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains(reason), "{config}: {error}");
        // Only a literal zero may be described as a "greater than zero" fault.
        if config["max_bytes"] != json!(0) {
            assert!(!error.contains("greater than zero"), "{config}: {error}");
        }
        // Never echo the supplied value.
        for withheld in ["1048576", "1024", "1.5", "-1"] {
            assert!(!error.contains(withheld), "{config}: {error}");
        }
    }
}

// === One 413 body for one policy ===

/// The plugin's three refusal points and the proxy core's streaming-overflow
/// refusal must give the client the same body for the same route policy.
#[tokio::test]
async fn every_plugin_413_is_the_shared_request_body_size_body() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 8})).unwrap();

    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "9".to_string());
    let declared = plugin.on_request_received(&mut ctx).await;

    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "9".to_string());
    let buffered = plugin.before_proxy(&mut ctx, &mut HashMap::new()).await;

    let headers = HashMap::new();
    let finalized = plugin.on_final_request_body(&headers, b"123456789").await;
    let mut ctx = make_ctx("POST", "/api");
    let finalized_with_context = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"123456789")
        .await;

    for (site, result) in [
        ("content-length", declared),
        ("buffered", buffered),
        ("final", finalized),
        ("final-with-context", finalized_with_context),
    ] {
        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 413, "{site}");
                assert_eq!(body, REQUEST_BODY_TOO_LARGE_BODY, "{site}");
            }
            other => panic!("{site}: expected 413 Reject, got {other:?}"),
        }
    }
    let parsed: serde_json::Value = serde_json::from_str(REQUEST_BODY_TOO_LARGE_BODY).unwrap();
    assert_eq!(parsed["error"], "Request body exceeds maximum size");
}

/// The proxy core's request-body-size refusals (H1/H2, native H3, the H3
/// bridge) and this plugin must not drift back to a second spelling of the
/// same refusal. The H3 bridge used to answer `{"error":"Request body too
/// large"}` while every other site answered the shared body.
#[test]
fn request_body_size_refusals_do_not_use_a_second_body() {
    for (file, source) in [
        (
            "src/proxy/mod.rs",
            include_str!("../../../src/proxy/mod.rs"),
        ),
        (
            "src/http3/server.rs",
            include_str!("../../../src/http3/server.rs"),
        ),
        (
            "src/http3/cross_protocol.rs",
            include_str!("../../../src/http3/cross_protocol.rs"),
        ),
        (
            "src/http3/client.rs",
            include_str!("../../../src/http3/client.rs"),
        ),
        (
            "src/plugins/request_size_limiting.rs",
            include_str!("../../../src/plugins/request_size_limiting.rs"),
        ),
    ] {
        assert!(
            !source.contains(r#""Request body too large""#),
            "{file} spells a request-body-size refusal other than REQUEST_BODY_TOO_LARGE_BODY"
        );
    }
}

// === Rejection metadata ===

fn metadata<'a>(ctx: &'a RequestContext, key: &str) -> Option<&'a str> {
    ctx.metadata.get(key).map(String::as_str)
}

#[tokio::test]
async fn content_length_rejection_records_reason_limit_observed_size_and_instance() {
    let plugin =
        RequestSizeLimiting::new_with_config_id(&json!({"max_bytes": 1024}), Some("rsl-uploads"))
            .unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "2048".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject {
            status_code: 413,
            ..
        }
    ));
    assert_eq!(
        metadata(&ctx, REJECTION_REASON_METADATA_KEY),
        Some("content_length_over_limit")
    );
    assert_eq!(
        metadata(&ctx, REJECTION_INSTANCE_METADATA_KEY),
        Some("rsl-uploads")
    );
    assert_eq!(metadata(&ctx, REJECTION_LIMIT_METADATA_KEY), Some("1024"));
    assert_eq!(
        metadata(&ctx, REJECTION_OBSERVED_METADATA_KEY),
        Some("2048")
    );
}

#[tokio::test]
async fn ambiguous_content_length_rejection_records_no_observed_size() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "2048, 4096".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject {
            status_code: 400,
            ..
        }
    ));
    assert_eq!(
        metadata(&ctx, REJECTION_REASON_METADATA_KEY),
        Some("content_length_ambiguous")
    );
    assert_eq!(
        metadata(&ctx, REJECTION_INSTANCE_METADATA_KEY),
        Some("standalone")
    );
    assert_eq!(metadata(&ctx, REJECTION_LIMIT_METADATA_KEY), Some("1024"));
    assert_eq!(metadata(&ctx, REJECTION_OBSERVED_METADATA_KEY), None);
}

#[tokio::test]
async fn buffered_body_rejection_records_the_observed_size() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 10})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.metadata
        .insert("request_body_size_bytes".to_string(), "11".to_string());

    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Reject {
            status_code: 413,
            ..
        }
    ));
    assert_eq!(
        metadata(&ctx, REJECTION_REASON_METADATA_KEY),
        Some("buffered_body_over_limit")
    );
    assert_eq!(metadata(&ctx, REJECTION_LIMIT_METADATA_KEY), Some("10"));
    assert_eq!(metadata(&ctx, REJECTION_OBSERVED_METADATA_KEY), Some("11"));
}

#[tokio::test]
async fn final_body_rejection_records_metadata_when_a_context_is_available() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 8})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    let headers = HashMap::new();

    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"12345678")
            .await,
        PluginResult::Continue
    ));
    assert_eq!(metadata(&ctx, REJECTION_REASON_METADATA_KEY), None);

    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, b"123456789")
            .await,
        PluginResult::Reject {
            status_code: 413,
            ..
        }
    ));
    assert_eq!(
        metadata(&ctx, REJECTION_REASON_METADATA_KEY),
        Some("final_body_over_limit")
    );
    assert_eq!(metadata(&ctx, REJECTION_LIMIT_METADATA_KEY), Some("8"));
    assert_eq!(metadata(&ctx, REJECTION_OBSERVED_METADATA_KEY), Some("9"));
    // Reporting metadata must not make the route pay a per-request context
    // clone for the final-body stage.
    assert!(!plugin.needs_final_request_body_context());
}

#[tokio::test]
async fn accepted_requests_record_no_rejection_metadata() {
    let plugin = RequestSizeLimiting::new(&json!({"max_bytes": 1024})).unwrap();
    let mut ctx = make_ctx("POST", "/api");
    ctx.headers
        .insert("content-length".to_string(), "1024".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut HashMap::new()).await,
        PluginResult::Continue
    ));
    for key in [
        REJECTION_REASON_METADATA_KEY,
        REJECTION_INSTANCE_METADATA_KEY,
        REJECTION_LIMIT_METADATA_KEY,
        REJECTION_OBSERVED_METADATA_KEY,
    ] {
        assert_eq!(metadata(&ctx, key), None, "{key}");
    }
}

/// The production factory hands the plugin-config id through, so the
/// transaction log names which configured instance refused the request.
#[tokio::test]
async fn factory_reports_the_plugin_config_id_as_the_rejecting_instance() {
    let plugin = ferrum_edge::plugins::create_plugin_with_http_client_and_config_id(
        "request_size_limiting",
        &json!({"max_bytes": 4}),
        ferrum_edge::plugins::PluginHttpClient::default(),
        Some("tenant-upload-limit"),
    )
    .unwrap()
    .unwrap();
    let mut ctx = make_ctx("PUT", "/upload");
    ctx.headers
        .insert("content-length".to_string(), "5".to_string());

    assert!(matches!(
        plugin.on_request_received(&mut ctx).await,
        PluginResult::Reject {
            status_code: 413,
            ..
        }
    ));
    assert_eq!(
        metadata(&ctx, REJECTION_INSTANCE_METADATA_KEY),
        Some("tenant-upload-limit")
    );
}

/// The factory contract: a supplied plugin-config id must be usable. A blank id
/// fails closed (as `request_mirror` does) instead of reporting `standalone`.
#[test]
fn blank_plugin_config_id_fails_closed() {
    let config = json!({"max_bytes": 1024});
    for blank in ["", "   "] {
        let error = match RequestSizeLimiting::new_with_config_id(&config, Some(blank)) {
            Ok(_) => panic!("blank id {blank:?} must be refused"),
            Err(error) => error,
        };
        assert!(
            error.contains("plugin_config_id must not be blank"),
            "{error}"
        );
        let factory_error = match ferrum_edge::plugins::create_plugin_with_http_client_and_config_id(
            "request_size_limiting",
            &config,
            ferrum_edge::plugins::PluginHttpClient::default(),
            Some(blank),
        ) {
            Ok(_) => panic!("factory must refuse blank id {blank:?}"),
            Err(error) => error,
        };
        assert!(
            factory_error.contains("plugin_config_id must not be blank"),
            "{factory_error}"
        );
    }
    // An absent id is the standalone default, not an error.
    assert!(RequestSizeLimiting::new_with_config_id(&config, None).is_ok());
}

/// The header-phase refusals record their metadata on the real request context
/// on every protocol; only the final-body refusal depends on a context being
/// handed to its hook. Pin both header-phase refusals through the production
/// factory, which is how the proxy builds the instance.
#[tokio::test]
async fn header_phase_rejections_record_metadata_through_the_factory() {
    let plugin = ferrum_edge::plugins::create_plugin_with_http_client_and_config_id(
        "request_size_limiting",
        &json!({"max_bytes": 16}),
        ferrum_edge::plugins::PluginHttpClient::default(),
        Some("edge-limit"),
    )
    .unwrap()
    .unwrap();

    for (content_length, status, reason, observed) in [
        ("17", 413, "content_length_over_limit", Some("17")),
        ("16, 17", 400, "content_length_ambiguous", None),
    ] {
        let mut ctx = make_ctx("POST", "/api");
        ctx.headers
            .insert("content-length".to_string(), content_length.to_string());
        match plugin.on_request_received(&mut ctx).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, status),
            other => panic!("{content_length}: expected Reject, got {other:?}"),
        }
        assert_eq!(metadata(&ctx, REJECTION_REASON_METADATA_KEY), Some(reason));
        assert_eq!(
            metadata(&ctx, REJECTION_INSTANCE_METADATA_KEY),
            Some("edge-limit")
        );
        assert_eq!(metadata(&ctx, REJECTION_LIMIT_METADATA_KEY), Some("16"));
        assert_eq!(metadata(&ctx, REJECTION_OBSERVED_METADATA_KEY), observed);
    }
}
