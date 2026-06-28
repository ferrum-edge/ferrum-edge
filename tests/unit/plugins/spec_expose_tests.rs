//! Tests for spec_expose plugin

use ferrum_edge::plugins::spec_expose::SpecExpose;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
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
    assert_eq!(plugin.priority(), priority::SPEC_EXPOSE);
    assert_eq!(plugin.priority(), 210);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.applies_after_proxy_on_reject());
    assert!(!plugin.is_auth_plugin());
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
fn test_creation_rejects_metadata_spec_url_under_default_policy() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    // spec_expose fetches its own URL; a literal metadata spec_url must be
    // rejected at config-load under the default dangerous-range baseline.
    let client = PluginHttpClient::default_with_backend_allow_ips(
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid"),
    );
    let err = SpecExpose::new(
        &json!({ "spec_url": "http://169.254.169.254/openapi.yaml" }),
        client,
    )
    .err()
    .unwrap();
    assert!(
        err.contains("169.254.169.254") && err.contains("backend egress policy"),
        "got: {err}"
    );

    // A loopback spec_url (in-cluster docs service) still constructs.
    let client = PluginHttpClient::default_with_backend_allow_ips(
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid"),
    );
    assert!(
        SpecExpose::new(
            &json!({ "spec_url": "http://127.0.0.1:8080/openapi.yaml" }),
            client
        )
        .is_ok()
    );
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

#[test]
fn test_creation_rejects_empty_authority_spec_url() {
    let err = SpecExpose::new(
        &json!({ "spec_url": "https:///openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("empty authority spec_url must be rejected");
    assert!(err.contains("hostname or IP address"), "got: {err}");
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
async fn test_exact_listen_path_continues() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "=/api");
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

#[test]
fn test_warmup_hostnames_unbrackets_ipv6_literal() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://[2001:db8::5]:9443/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    assert_eq!(plugin.warmup_hostnames(), vec!["2001:db8::5"]);
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
fn test_creation_rejects_empty_content_type_override() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": "   "
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("empty content_type override must be rejected");
    assert!(err.contains("content_type"), "got: {err}");
}

#[test]
fn test_creation_rejects_invalid_content_type_header_value() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": "application/yaml\r\nx-bad: yes"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("invalid content_type header value must be rejected");
    assert!(err.contains("content_type"), "got: {err}");
}

#[test]
fn test_creation_rejects_non_bool_tls_no_verify() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "tls_no_verify": "true"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("tls_no_verify must be boolean");
    assert!(err.contains("tls_no_verify"), "got: {err}");
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

#[test]
fn test_creation_rejects_non_integer_max_response_body_bytes() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "max_response_body_bytes": "large"
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("non-integer max_response_body_bytes must be rejected");
    assert!(err.contains("max_response_body_bytes"), "got: {err}");
}

#[test]
fn test_creation_rejects_zero_max_response_body_bytes() {
    let err = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "max_response_body_bytes": 0
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("zero max_response_body_bytes must be rejected");
    assert!(err.contains("greater than zero"), "got: {err}");
}

#[tokio::test]
async fn test_specz_request_fetches_mocked_spec_and_preserves_content_type() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"openapi: 3.0.0\n".to_vec())
                .insert_header("content-type", "application/yaml"),
        )
        .expect(1)
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
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body, bytes::Bytes::from_static(b"openapi: 3.0.0\n"));
            assert_eq!(headers.get("content-type").unwrap(), "application/yaml");
            // Finding #68: the served /specz response always carries nosniff.
            assert_eq!(
                headers.get("x-content-type-options").map(String::as_str),
                Some("nosniff")
            );
        }
        other => panic!("expected RejectBinary, got {other:?}"),
    }
}

/// Finding #68: an attacker-controllable upstream must not be able to make the
/// unauthenticated /specz endpoint serve `text/html`. The upstream-derived
/// content-type is constrained to an allow-list of spec media types and falls
/// back to `application/octet-stream` for anything else, and `nosniff` is set.
#[tokio::test]
async fn test_specz_sanitizes_untrusted_upstream_content_type() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"<script>alert(1)</script>".to_vec())
                .insert_header("content-type", "text/html; charset=utf-8"),
        )
        .expect(1)
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
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 200);
            // text/html is NOT in the spec allow-list → inert fallback.
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/octet-stream")
            );
            assert_eq!(
                headers.get("x-content-type-options").map(String::as_str),
                Some("nosniff")
            );
        }
        other => panic!("expected RejectBinary, got {other:?}"),
    }
}

/// Unit-level coverage of the allow-list itself (finding #68).
#[test]
fn test_sanitize_upstream_content_type_allow_list() {
    use ferrum_edge::plugins::spec_expose::sanitize_upstream_content_type as sanitize;

    // Allowed spec media types pass through verbatim, including parameters.
    for allowed in [
        "application/json",
        "application/openapi+json",
        "application/openapi+yaml",
        "application/yaml",
        "application/vnd.oai.openapi",
        "application/vnd.oai.openapi+json",
        "application/wsdl+xml",
        "application/vnd.sun.wadl+xml",
        "text/yaml",
        "application/x-yaml",
        "application/xml",
        "text/xml",
        "text/plain",
    ] {
        assert_eq!(sanitize(allowed), allowed);
    }
    // Case-insensitive media type, charset parameter preserved.
    assert_eq!(
        sanitize("Application/JSON; charset=utf-8"),
        "Application/JSON; charset=utf-8"
    );
    assert_eq!(
        sanitize("application/vnd.oai.openapi+json;version=3.0"),
        "application/vnd.oai.openapi+json;version=3.0"
    );
    assert_eq!(
        sanitize("application/vnd.oai.openapi;version=3.0"),
        "application/vnd.oai.openapi;version=3.0"
    );
    assert_eq!(
        sanitize("  application/yaml  ; q=1"),
        "  application/yaml  ; q=1"
    );

    // Anything outside the allow-list collapses to the inert fallback.
    for bad in [
        "text/html",
        "text/html; charset=utf-8",
        "application/javascript",
        "image/svg+xml",
        "",
        "garbage",
    ] {
        assert_eq!(sanitize(bad), "application/octet-stream");
    }
}

#[tokio::test]
async fn test_specz_request_allows_custom_cap_at_exact_body_size() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    let body = b"openapi\n".to_vec();
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(body.clone())
                .insert_header("content-type", "application/yaml"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "max_response_body_bytes": body.len()
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let result = plugin.on_request_received(&mut ctx).await;
    match result {
        PluginResult::RejectBinary {
            status_code,
            body: returned_body,
            headers,
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(returned_body, bytes::Bytes::from(body));
            assert_eq!(headers.get("content-type").unwrap(), "application/yaml");
        }
        other => panic!("expected RejectBinary, got {other:?}"),
    }
}

#[tokio::test]
async fn test_specz_request_rejects_oversized_content_length_spec_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_bytes(b"openapi: 3.0.0\ninfo: too large\n".to_vec()),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "max_response_body_bytes": 8
        }),
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
            assert!(body.contains("too large"), "got: {body}");
            assert!(!body.contains("max_response_body_bytes"), "got: {body}");
        }
        other => panic!("expected Reject, got {other:?}"),
    }
}

#[tokio::test]
async fn test_specz_request_rejects_oversized_chunked_spec_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, timeout};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        // The timeout below guards against this raw fixture hanging if the
        // request/response plumbing changes.
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 8192 {
                break;
            }
        }
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/yaml\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for chunk in [
            b"openapi: ".as_slice(),
            b"3.0.0\n".as_slice(),
            b"info: too large\n".as_slice(),
        ] {
            let head = format!("{:x}\r\n", chunk.len());
            if socket.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            if socket.write_all(chunk).await.is_err() {
                return;
            }
            if socket.write_all(b"\r\n").await.is_err() {
                return;
            }
            if socket.flush().await.is_err() {
                return;
            }
            // Best effort: separate writes make the fixture exercise the
            // no-Content-Length streaming path even if the OS later coalesces
            // some chunks before reqwest yields them.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let _ = socket.write_all(b"0\r\n\r\n").await;
    });

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("http://{addr}/openapi.yaml"),
            "max_response_body_bytes": 16
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let result = plugin.on_request_received(&mut ctx).await;
    timeout(Duration::from_secs(5), server)
        .await
        .expect("raw spec server timed out")
        .expect("raw spec server panicked");

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 502);
            assert!(body.contains("too large"), "got: {body}");
            assert!(!body.contains("max_response_body_bytes"), "got: {body}");
        }
        other => panic!("expected Reject, got {other:?}"),
    }
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
                .set_body_bytes(b"openapi: 3.0.0\n".to_vec()),
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
                .set_body_bytes(b"openapi: 3.0.0\n".to_vec()),
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
                .set_body_bytes(b"openapi: 3.0.0\n".to_vec()),
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

#[tokio::test]
async fn test_cache_does_not_store_oversized_fetches() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"too large body".to_vec()))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_bytes(b"ok\n".to_vec()),
        )
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "cache_ttl_seconds": 60,
            "max_response_body_bytes": 8
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let r1 = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        r1,
        PluginResult::Reject {
            status_code: 502,
            ..
        }
    ));

    let mut ctx2 = make_ctx("GET", "/api/specz", "/api");
    let r2 = plugin.on_request_received(&mut ctx2).await;
    match r2 {
        PluginResult::RejectBinary {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 200);
            assert_eq!(body, bytes::Bytes::from_static(b"ok\n"));
        }
        other => panic!("expected RejectBinary, got {other:?}"),
    }
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
                .set_body_bytes(b"openapi: 3.0.0\n".to_vec())
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
                .set_body_bytes(b"openapi: 3.0.0\n".to_vec())
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
