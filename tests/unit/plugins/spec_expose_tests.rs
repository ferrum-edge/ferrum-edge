//! Tests for spec_expose plugin

use ferrum_edge::plugins::spec_expose::SpecExpose;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::sync::Arc;

use super::plugin_utils::create_test_proxy;

fn make_proxy_with_listen_path(listen_path: &str) -> Arc<ferrum_edge::config::types::Proxy> {
    let mut proxy = create_test_proxy();
    proxy.listen_path = listen_path.to_string();
    Arc::new(proxy)
}

fn make_ctx(method: &str, full_path: &str, listen_path: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        full_path.to_string(),
    );
    ctx.matched_proxy = Some(make_proxy_with_listen_path(listen_path));
    ctx
}

// === Plugin creation ===

#[test]
fn test_creation_valid_config() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
    let plugin = plugin.unwrap();
    assert_eq!(plugin.name(), "spec_expose");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::SPEC_EXPOSE
    );
}

#[test]
fn test_creation_with_content_type_override() {
    let plugin = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": "application/yaml"
        }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_creation_with_tls_no_verify() {
    let plugin = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "tls_no_verify": true
        }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_creation_missing_spec_url() {
    let err = SpecExpose::new(&json!({}), PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("spec_url"));
}

#[test]
fn test_creation_empty_spec_url() {
    let err = SpecExpose::new(&json!({ "spec_url": "" }), PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("spec_url"));
}

#[test]
fn test_creation_default_spec_url_rejected() {
    let err = SpecExpose::new(
        &json!({ "spec_url": "default" }),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(err.contains("spec_url"));
}

#[test]
fn test_creation_invalid_url() {
    let err = SpecExpose::new(
        &json!({ "spec_url": "not a url" }),
        PluginHttpClient::default(),
    )
    .err()
    .unwrap();
    assert!(err.contains("not a valid URL"));
}

// === Path matching ===

#[test]
fn test_is_specz_request_root_listen_path() {
    assert!(SpecExpose::is_specz_request("/specz", "/"));
    assert!(!SpecExpose::is_specz_request("/other", "/"));
    assert!(!SpecExpose::is_specz_request("/specz/extra", "/"));
    assert!(!SpecExpose::is_specz_request("/", "/"));
}

#[test]
fn test_is_specz_request_nested_listen_path() {
    assert!(SpecExpose::is_specz_request("/api/v1/specz", "/api/v1"));
    assert!(!SpecExpose::is_specz_request("/api/v1", "/api/v1"));
    assert!(!SpecExpose::is_specz_request("/api/v1/other", "/api/v1"));
    assert!(!SpecExpose::is_specz_request(
        "/api/v1/specz/extra",
        "/api/v1"
    ));
}

#[test]
fn test_is_specz_request_single_segment_listen_path() {
    assert!(SpecExpose::is_specz_request("/api/specz", "/api"));
    assert!(!SpecExpose::is_specz_request("/api", "/api"));
}

// === on_request_received behaviour ===

#[tokio::test]
async fn test_non_get_request_continues() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("POST", "/api/specz", "/api");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_non_specz_path_continues() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/users", "/api");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_regex_listen_path_continues() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "~/api.*");
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_no_matched_proxy_continues() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/specz".to_string(),
    );
    // matched_proxy is None
    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_specz_request_with_unreachable_url_returns_502() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "http://127.0.0.1:1/nonexistent" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("Failed to fetch"));
        }
        _ => panic!("expected Reject"),
    }
}

// === Supported protocols ===

#[test]
fn test_supported_protocols_http_only() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(
        plugin.supported_protocols(),
        ferrum_edge::plugins::HTTP_ONLY_PROTOCOLS
    );
}

// === Warmup hostnames ===

#[test]
fn test_warmup_hostnames() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://internal.example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["internal.example.com"]);
}
