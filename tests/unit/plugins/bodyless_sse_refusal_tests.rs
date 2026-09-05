//! No-content representation metadata must not activate whole-body SSE refusal (#4648).

use ferrum_edge::_test_support::{
    run_after_proxy_hooks_for_test, stamp_original_response_metadata_for_test,
};
use ferrum_edge::plugins::ai_response_guard::AiResponseGuard;
use ferrum_edge::plugins::body_validator::BodyValidator;
use ferrum_edge::plugins::openapi_validator::OpenapiValidator;
use ferrum_edge::plugins::response_size_limiting::ResponseSizeLimiting;
use ferrum_edge::plugins::response_transformer::ResponseTransformer;
use ferrum_edge::plugins::waf::Waf;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn policies() -> Vec<Arc<dyn Plugin>> {
    let operations = ["GET", "HEAD"].map(|method| {
        json!({
            "method": method,
            "path_template": "/events",
            "path_regex": "^/events$",
            "responses": {"200": {"application/json": {"type": "object"}}}
        })
    });
    vec![
        Arc::new(
            ResponseSizeLimiting::new(&json!({
                "max_bytes": 1000,
                "require_buffered_check": true
            }))
            .expect("size policy"),
        ),
        Arc::new(
            BodyValidator::new(&json!({"response_json_schema": {"type": "object"}}))
                .expect("body validator"),
        ),
        Arc::new(
            OpenapiValidator::new(&json!({
                "enforcement_mode": "block",
                "validate_response": true,
                "operations": operations
            }))
            .expect("OpenAPI validator"),
        ),
        Arc::new(
            AiResponseGuard::new(&json!({"require_json": true, "action": "reject"}))
                .expect("AI response guard"),
        ),
        Arc::new(
            Waf::new(&json!({
                "include_default_rules": false,
                "response_inspection": true,
                "response_body_inspection": true,
                "custom_rules": [{
                    "id": "BODY-BLOCK",
                    "name": "Block response text",
                    "category": "custom",
                    "severity": "critical",
                    "target": "response_body",
                    "match_kind": "contains",
                    "pattern": "forbidden",
                    "action": "enforce"
                }]
            }))
            .expect("WAF"),
        ),
    ]
}

fn context(method: &str) -> RequestContext {
    RequestContext::new("127.0.0.1".into(), method.into(), "/events".into())
}

fn headers(content_type: &str) -> HashMap<String, String> {
    HashMap::from([("content-type".into(), content_type.into())])
}

async fn assert_no_content_matrix(plugin: &dyn Plugin) {
    for method in ["HEAD", "GET"] {
        for status in [100, 101, 103, 199, 200, 204, 205, 304] {
            if method == "GET" && status == 200 {
                continue;
            }
            for content_type in ["text/event-stream", "application/json"] {
                let mut ctx = context(method);
                let mut response_headers = headers(content_type);
                // This is representation metadata, not transferable content.
                response_headers.insert("content-length".into(), "4096".into());
                stamp_original_response_metadata_for_test(&mut ctx, status, &response_headers);
                assert_eq!(plugin.should_buffer_response_body(&ctx), method != "HEAD");
                assert!(!plugin.should_buffer_response_body_for_content_type(
                    &ctx,
                    Some(content_type),
                    status,
                    &response_headers,
                ));
                if method != "HEAD" {
                    assert!(plugin.should_release_response_body_under_retries(
                        &ctx,
                        status,
                        &response_headers,
                    ));
                    assert!(
                        plugin.should_release_response_body_before_content_type_rewrite(
                            &ctx,
                            status,
                            &response_headers,
                        )
                    );
                }
                assert!(
                    matches!(
                        plugin
                            .after_proxy(&mut ctx, status, &mut response_headers)
                            .await,
                        PluginResult::Continue
                    ),
                    "{} rejected {method}/{status}/{content_type}",
                    plugin.name()
                );
                assert!(
                    matches!(
                        plugin
                            .on_final_response_body(&mut ctx, status, &response_headers, b"")
                            .await,
                        PluginResult::Continue
                    ),
                    "{} rejected the empty final body",
                    plugin.name()
                );
            }
        }
    }
}

#[tokio::test]
async fn response_size_limiting_no_content_matrix() {
    assert_no_content_matrix(policies()[0].as_ref()).await;
}

#[tokio::test]
async fn body_validator_no_content_matrix() {
    assert_no_content_matrix(policies()[1].as_ref()).await;
}

#[tokio::test]
async fn openapi_validator_no_content_matrix() {
    assert_no_content_matrix(policies()[2].as_ref()).await;
}

#[tokio::test]
async fn ai_response_guard_no_content_matrix() {
    assert_no_content_matrix(policies()[3].as_ref()).await;
}

#[tokio::test]
async fn waf_no_content_matrix() {
    assert_no_content_matrix(policies()[4].as_ref()).await;
}

#[tokio::test]
async fn genuine_sse_refusal_preserves_original_header_provenance() {
    for plugin in policies() {
        for live_type in ["text/event-stream", "application/json"] {
            let mut ctx = context("GET");
            ctx.headers
                .insert("accept".into(), "text/event-stream".into());
            assert!(plugin.should_buffer_response_body(&ctx));
            stamp_original_response_metadata_for_test(&mut ctx, 200, &headers("text/event-stream"));
            let mut response_headers = headers(live_type);
            let result = plugin
                .after_proxy(&mut ctx, 200, &mut response_headers)
                .await;
            let expected_status = if plugin.name() == "waf" { 403 } else { 502 };
            assert!(
                matches!(result, PluginResult::Reject { status_code, .. }
                    if status_code == expected_status),
                "{} must refuse real SSE",
                plugin.name()
            );
        }
    }
}

#[tokio::test]
async fn body_bearing_responses_still_enforce_final_body_policy() {
    for plugin in policies() {
        let mut ctx = context("GET");
        let response_headers = headers("application/json");
        let body = if plugin.name() == "response_size_limiting" {
            vec![b'x'; 1001]
        } else {
            b"forbidden".to_vec()
        };
        assert!(matches!(
            plugin
                .on_final_response_body(&mut ctx, 200, &response_headers, &body)
                .await,
            PluginResult::Reject { .. }
        ));
    }
}

#[tokio::test]
async fn composed_policies_preserve_no_content_status_and_header_hooks() {
    let mut plugins = policies();
    plugins.truncate(2);
    plugins.push(Arc::new(
        ResponseTransformer::new(&json!({"rules": [{
            "operation": "add", "target": "header", "key": "x-checked", "value": "yes"
        }]}))
        .expect("header transformer"),
    ));
    for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 205), ("GET", 304)] {
        let mut ctx = context(method);
        let mut response_headers = headers("text/event-stream");
        assert!(
            !run_after_proxy_hooks_for_test(&plugins, &mut ctx, status, &mut response_headers)
                .await
        );
        assert_eq!(
            response_headers.get("x-checked").map(String::as_str),
            Some("yes")
        );
        for plugin in &plugins {
            assert!(matches!(
                plugin
                    .on_final_response_body(&mut ctx, status, &response_headers, b"")
                    .await,
                PluginResult::Continue
            ));
        }
    }
    let mut ctx = context("GET");
    assert!(
        run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers("text/event-stream"))
            .await
    );
}

#[tokio::test]
async fn no_content_exemption_does_not_bypass_waf_header_policy() {
    let plugin = Waf::new(&json!({
        "include_default_rules": false,
        "response_inspection": true,
        "custom_rules": [{
            "id": "HEADER-BLOCK",
            "name": "Block sensitive header",
            "category": "custom",
            "severity": "critical",
            "target": "response_headers",
            "match_kind": "contains",
            "pattern": "sensitive-value",
            "action": "enforce"
        }]
    }))
    .expect("WAF header policy");
    for (method, status) in [("HEAD", 200), ("GET", 204), ("GET", 205), ("GET", 304)] {
        let mut ctx = context(method);
        let mut response_headers = headers("text/event-stream");
        response_headers.insert("x-private".into(), "sensitive-value".into());
        assert!(matches!(
            plugin
                .after_proxy(&mut ctx, status, &mut response_headers)
                .await,
            PluginResult::Reject { .. }
        ));
    }
}
