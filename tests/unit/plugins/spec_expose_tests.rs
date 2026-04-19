//! Tests for spec_expose plugin

use ferrum_edge::plugins::spec_expose::SpecExpose;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::json;
use std::sync::Arc;

use super::plugin_utils::create_test_proxy;

fn make_proxy_with_listen_path(listen_path: &str) -> Arc<ferrum_edge::config::types::Proxy> {
    let mut proxy = create_test_proxy();
    proxy.listen_path = Some(listen_path.to_string());
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

// === Constructor validation ===

#[test]
fn test_creation_rejects_non_http_scheme() {
    let err = SpecExpose::new(
        &json!({ "spec_url": "file:///etc/passwd" }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-http scheme must be rejected");
    assert!(err.contains("http or https"), "got: {err}");
}

#[test]
fn test_creation_rejects_non_string_content_type() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": 42
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-string content_type must be rejected");
    assert!(
        err.contains("'content_type' must be a string"),
        "got: {err}"
    );
}

#[test]
fn test_creation_rejects_non_integer_cache_ttl() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "cache_ttl_seconds": "forever"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-integer cache_ttl_seconds must be rejected");
    assert!(err.contains("cache_ttl_seconds"), "got: {err}");
}

#[test]
fn test_creation_accepts_zero_cache_ttl() {
    // Zero TTL = caching disabled — should not error
    let plugin = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "cache_ttl_seconds": 0
        }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

// === Caching behavior ===

#[tokio::test]
async fn test_cache_hits_avoid_repeat_fetches() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_string("openapi: 3.0.0\n"),
        )
        .expect(1) // Critical: we expect EXACTLY 1 upstream fetch
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "cache_ttl_seconds": 60
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let r1 = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        r1,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));

    let mut ctx2 = make_ctx("GET", "/api/specz", "/api");
    let r2 = plugin.on_request_received(&mut ctx2).await;
    assert!(matches!(
        r2,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));

    // Drop drains expectations: panics if upstream was hit anything other than once
}

#[tokio::test]
async fn test_cache_disabled_when_ttl_zero() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_string("openapi: 3.0.0\n"),
        )
        .expect(2) // ttl=0 means every request re-fetches
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "cache_ttl_seconds": 0
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    for _ in 0..2 {
        let mut ctx = make_ctx("GET", "/api/specz", "/api");
        let r = plugin.on_request_received(&mut ctx).await;
        assert!(matches!(
            r,
            PluginResult::RejectBinary {
                status_code: 200,
                ..
            }
        ));
    }
}

#[tokio::test]
async fn test_cache_does_not_store_failed_fetches() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // First mock: returns 500 — should NOT be cached
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    // Second mock: returns 200
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_string("openapi: 3.0.0\n"),
        )
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "cache_ttl_seconds": 60
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // First request: 502 (upstream returned 500)
    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let r1 = plugin.on_request_received(&mut ctx).await;
    match r1 {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 502),
        other => panic!("expected Reject, got {other:?}"),
    }

    // Second request: should re-fetch (failures are not cached) and succeed
    let mut ctx2 = make_ctx("GET", "/api/specz", "/api");
    let r2 = plugin.on_request_received(&mut ctx2).await;
    assert!(matches!(
        r2,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
}

// Regression: cold-cache concurrent requests must not all fan out to the
// upstream. The single-flight guard inside on_request_received serializes
// cache-miss fetches so the upstream sees exactly one request even when
// dozens of /specz calls arrive simultaneously.
#[tokio::test]
async fn test_concurrent_cold_cache_fetches_deduplicated() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_string("openapi: 3.0.0\n")
                // Slow the upstream so concurrent fetches actually race.
                .set_delay(std::time::Duration::from_millis(150)),
        )
        // Critical: only ONE upstream fetch even with N concurrent callers.
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = Arc::new(
        SpecExpose::new(
            &json!({
                "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
                "cache_ttl_seconds": 60
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );

    // Fire 8 concurrent requests against a cold cache.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let plugin = plugin.clone();
        handles.push(tokio::spawn(async move {
            let mut ctx = make_ctx("GET", "/api/specz", "/api");
            plugin.on_request_received(&mut ctx).await
        }));
    }
    for h in handles {
        let result = h.await.unwrap();
        assert!(matches!(
            result,
            PluginResult::RejectBinary {
                status_code: 200,
                ..
            }
        ));
    }
    // MockServer drops with .expect(1) — panics if more than one hit.
}

// Regression for Codex P2: when caching is disabled (TTL=0), the single-flight
// lock must NOT serialize requests. Every request is expected to re-fetch, so
// the lock would collapse concurrent throughput into strictly-sequential
// upstream calls. This test verifies that N concurrent requests fire all N
// upstream fetches in parallel within a timing budget that proves they did
// not serialize behind a lock.
#[tokio::test]
async fn test_ttl_zero_does_not_serialize_concurrent_fetches() {
    use std::time::Instant;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // Each upstream fetch takes ~150ms. With 6 requests, serialized execution
    // would take ~900ms. Concurrent execution should finish in ~200ms.
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_string("openapi: 3.0.0\n")
                .set_delay(std::time::Duration::from_millis(150)),
        )
        // TTL=0 means every request re-fetches — we expect ALL 6 hits.
        .expect(6)
        .mount(&mock_server)
        .await;

    let plugin = Arc::new(
        SpecExpose::new(
            &json!({
                "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
                "cache_ttl_seconds": 0
            }),
            PluginHttpClient::default(),
        )
        .unwrap(),
    );

    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..6 {
        let plugin = plugin.clone();
        handles.push(tokio::spawn(async move {
            let mut ctx = make_ctx("GET", "/api/specz", "/api");
            plugin.on_request_received(&mut ctx).await
        }));
    }
    for h in handles {
        let result = h.await.unwrap();
        assert!(matches!(
            result,
            PluginResult::RejectBinary {
                status_code: 200,
                ..
            }
        ));
    }
    let elapsed = start.elapsed();
    // Serialized would be ~900ms. Parallel should be ~150-300ms. Allow a
    // generous 600ms ceiling to avoid flakiness on slow CI, but anything
    // >600ms indicates the lock is serializing.
    assert!(
        elapsed < std::time::Duration::from_millis(600),
        "TTL=0 concurrent fetches appear serialized (took {elapsed:?}, expected <600ms)"
    );
}
