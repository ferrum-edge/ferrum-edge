//! Tests for spec_expose plugin

use ferrum_edge::config::{BackendEgressPolicy, PoolConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::spec_expose::SpecExpose;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
use serde_json::json;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

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

fn reject_parts(result: PluginResult) -> (u16, Vec<u8>, std::collections::HashMap<String, String>) {
    match result {
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
        PluginResult::Continue => panic!("expected plugin rejection"),
    }
}

fn plugin_http_client_with_ca(ca_path: &str, tls_no_verify: bool) -> PluginHttpClient {
    PluginHttpClient::new(
        &PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        1_000,
        0,
        100,
        tls_no_verify,
        Some(ca_path),
        Arc::new(Vec::new()),
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        BackendEgressPolicy::unrestricted(),
        Arc::new(Vec::new()),
        0,
    )
}

#[derive(Clone, Default)]
struct SharedWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn contents(&self) -> String {
        String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap_or_default()
    }
}

struct SharedGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for SharedGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SharedGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
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
    assert!(!plugin.may_replace_rejection_response());
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

#[test]
fn test_is_specz_request_normalizes_trailing_separator_and_rejects_aliases() {
    for listen_path in ["/api", "/api/"] {
        assert!(SpecExpose::is_specz_request("/api/specz", listen_path));
        assert!(SpecExpose::is_specz_request(
            "/api/specz?download=true",
            listen_path
        ));
        assert!(!SpecExpose::is_specz_request("/api//specz", listen_path));
    }
    assert!(!SpecExpose::is_specz_request("/api%2Fspecz", "/api"));
    assert!(!SpecExpose::is_specz_request("/api/specz%2Fextra", "/api"));
    assert!(!SpecExpose::is_specz_request("/api/%73pecz", "/api"));
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
async fn test_host_only_proxy_continues() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut proxy = create_test_proxy();
    proxy.listen_path = None;
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/specz".to_string(),
    );
    ctx.matched_proxy = Some(Arc::new(proxy));

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

#[tokio::test(flavor = "current_thread")]
async fn test_failure_diagnostics_never_include_spec_path_query_or_fragment() {
    let writer = SharedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let secret_path = "private-never-log-this";
    let secret_query = "signed-token-never-log-this";
    let secret_fragment = "fragment-never-log-this";
    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!(
                "http://127.0.0.1:1/{secret_path}?token={secret_query}#{secret_fragment}"
            )
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    assert_eq!(plugin.warmup_hostnames(), vec!["127.0.0.1"]);

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let (status, body, _) = reject_parts(plugin.on_request_received(&mut ctx).await);
    assert_eq!(status, 502);
    let public_error = String::from_utf8(body).expect("JSON error is UTF-8");
    let logs = writer.contents();
    for secret in [secret_path, secret_query, secret_fragment] {
        assert!(!logs.contains(secret), "logs exposed {secret}: {logs}");
        assert!(
            !public_error.contains(secret),
            "public error exposed {secret}: {public_error}"
        );
    }
    assert!(logs.contains("spec_origin=http://127.0.0.1:1"), "{logs}");
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
fn test_creation_requires_top_level_object() {
    for config in [json!(null), json!([]), json!("spec")] {
        let error = SpecExpose::new(&config, PluginHttpClient::default())
            .err()
            .expect("non-object config must be rejected");
        assert!(error.contains("configuration must be an object"), "{error}");
    }
}

#[test]
fn test_creation_rejects_all_unknown_keys_with_actionable_error() {
    let error = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "cache_ttl_second": 30,
            "tls_no_verfy": true
        }),
        PluginHttpClient::default(),
    )
    .err()
    .expect("unknown config keys must be rejected");

    assert!(error.contains("'cache_ttl_second'"), "{error}");
    assert!(error.contains("'tls_no_verfy'"), "{error}");
    assert!(error.contains("supported keys"), "{error}");
}

#[test]
fn test_creation_accepts_explicit_null_for_every_optional_field() {
    let plugin = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "content_type": null,
            "tls_no_verify": null,
            "cache_ttl_seconds": null,
            "max_response_body_bytes": null
        }),
        PluginHttpClient::default(),
    );
    assert!(plugin.is_ok());
}

#[test]
fn test_creation_rejects_url_userinfo_without_echoing_credentials() {
    for spec_url in [
        "https://user:never-print-this@example.com/openapi.yaml",
        "https://user%40example.com@example.com/openapi.yaml",
        "https://:never-print-this@example.com/openapi.yaml",
        "https://@example.com/openapi.yaml",
    ] {
        let error = SpecExpose::new(
            &json!({ "spec_url": spec_url }),
            PluginHttpClient::default(),
        )
        .err()
        .expect("URL userinfo must be rejected");
        assert!(error.contains("must not contain URL userinfo"), "{error}");
        assert!(!error.contains("never-print-this"), "{error}");
        assert!(!error.contains("user%40example.com"), "{error}");
    }
}

#[test]
fn test_creation_fails_closed_when_configured_ca_cannot_be_loaded_or_parsed() {
    let missing_path = "/definitely/missing/spec-expose-ca.pem";
    let missing_error = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        plugin_http_client_with_ca(missing_path, false),
    )
    .err()
    .expect("missing configured CA must reject construction");
    assert!(missing_error.contains("refusing to widen trust"));

    let tempdir = tempfile::tempdir().expect("create tempdir");
    let invalid_path = tempdir.path().join("invalid-ca.pem");
    std::fs::write(&invalid_path, "not a certificate").expect("write invalid CA");
    let invalid_error = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        plugin_http_client_with_ca(invalid_path.to_str().expect("utf8 path"), false),
    )
    .err()
    .expect("invalid configured CA must reject construction");
    assert!(invalid_error.contains("refusing to widen trust"));
}

#[test]
fn test_creation_accepts_all_certificates_in_a_configured_ca_bundle() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let bundle_path = tempdir.path().join("ca-bundle.pem");
    let certificate = include_str!("../../certs/server.crt");
    std::fs::write(&bundle_path, format!("{certificate}\n{certificate}")).expect("write CA bundle");

    let result = SpecExpose::new(
        &json!({ "spec_url": "https://example.com/openapi.yaml" }),
        plugin_http_client_with_ca(bundle_path.to_str().expect("utf8 path"), false),
    );
    assert!(result.is_ok());
}

#[test]
fn test_tls_no_verify_explicitly_overrides_unreadable_ca() {
    let result = SpecExpose::new(
        &json!({
            "spec_url": "https://example.com/openapi.yaml",
            "tls_no_verify": true
        }),
        plugin_http_client_with_ca("/definitely/missing/spec-expose-ca.pem", false),
    );
    assert!(result.is_ok());
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
    // Zero TTL disables durable caching but retains burst coalescing.
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
            assert_eq!(
                headers.get("content-length").map(String::as_str),
                Some("15")
            );
            // Finding #68: the served /specz response always carries nosniff.
            assert_eq!(
                headers.get("x-content-type-options").map(String::as_str),
                Some("nosniff")
            );
        }
        other => panic!("expected RejectBinary, got {other:?}"),
    }
}

#[tokio::test]
async fn test_head_fetches_get_representation_without_rejection_replacement() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BODY: &[u8] = b"openapi: 3.1.0\n";
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/yaml")
                .set_body_bytes(BODY.to_vec()),
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

    let mut head_ctx = make_ctx("HEAD", "/api/specz", "/api/");
    let (head_status, head_representation, mut head_headers) =
        reject_parts(plugin.on_request_received(&mut head_ctx).await);
    assert_eq!(head_status, 200);
    assert_eq!(head_representation, BODY);
    assert_eq!(
        head_headers.get("content-type").map(String::as_str),
        Some("application/yaml")
    );
    assert_eq!(
        head_headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok()),
        Some(BODY.len())
    );
    assert_eq!(
        head_headers
            .get("x-content-type-options")
            .map(String::as_str),
        Some("nosniff")
    );

    // The plugin retains the full GET representation for response-body hooks
    // and does not enter the warning-producing rejection-replacement path.
    // The shared finalizer suppresses the finalized HEAD wire body.
    assert!(matches!(
        plugin
            .after_proxy(&mut head_ctx, head_status, &mut head_headers)
            .await,
        PluginResult::Continue
    ));

    let mut get_ctx = make_ctx("GET", "/api/specz?download=true", "/api/");
    let (get_status, get_body, get_headers) =
        reject_parts(plugin.on_request_received(&mut get_ctx).await);
    assert_eq!(get_status, head_status);
    assert_eq!(get_body, BODY);
    assert_eq!(get_headers, head_headers);
}

#[tokio::test]
async fn test_head_failure_has_get_metadata_without_rejection_replacement() {
    let plugin = SpecExpose::new(
        &json!({ "spec_url": "http://127.0.0.1:1/private?token=secret" }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("HEAD", "/api/specz", "/api");
    let (status, representation, mut headers) =
        reject_parts(plugin.on_request_received(&mut ctx).await);
    assert_eq!(status, 502);
    assert!(!representation.is_empty());
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert!(
        headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|value| value > 0)
    );
    assert_eq!(headers.get("retry-after").map(String::as_str), Some("1"));

    assert!(matches!(
        plugin.after_proxy(&mut ctx, status, &mut headers).await,
        PluginResult::Continue
    ));
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

#[tokio::test]
async fn test_explicit_content_type_override_bypasses_upstream_allow_list() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"openapi: 3.1.0\n".to_vec())
                .insert_header("content-type", "text/html"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let plugin = SpecExpose::new(
        &json!({
            "spec_url": format!("{}/openapi.yaml", mock_server.uri()),
            "content_type": "application/vnd.example.contract"
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("GET", "/api/specz", "/api");
    let (_, _, headers) = reject_parts(plugin.on_request_received(&mut ctx).await);
    assert_eq!(
        headers.get("content-type").map(String::as_str),
        Some("application/vnd.example.contract")
    );
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
        .expect(2) // Sequential requests belong to distinct fetch generations.
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

    let mut first_ctx = make_ctx("GET", "/api/specz", "/api");
    let first = plugin.on_request_received(&mut first_ctx).await;
    assert!(matches!(
        first,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
    let mut second_ctx = make_ctx("GET", "/api/specz", "/api");
    let second = plugin.on_request_received(&mut second_ctx).await;
    assert!(matches!(
        second,
        PluginResult::RejectBinary {
            status_code: 200,
            ..
        }
    ));
}

#[tokio::test]
async fn test_cache_does_not_store_failed_fetches() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    // First mock: returns 500 and enters the short negative-cache window.
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

    // The short negative-cache window must elapse before recovery is retried.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    // Second request: re-fetches after backoff and succeeds.
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

    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
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

#[tokio::test(start_paused = true)]
async fn test_failed_fetch_burst_is_single_flight_with_bounded_waiters() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_millis(250)))
        .expect(1)
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

    let mut handles = Vec::new();
    for _ in 0..96 {
        let plugin = Arc::clone(&plugin);
        handles.push(tokio::spawn(async move {
            let mut ctx = make_ctx("GET", "/api/specz", "/api");
            plugin.on_request_received(&mut ctx).await
        }));
    }

    let mut upstream_failures = 0;
    let mut busy_rejections = 0;
    for handle in handles {
        let (status, body, headers) = reject_parts(handle.await.expect("request task"));
        match status {
            502 => upstream_failures += 1,
            503 => {
                busy_rejections += 1;
                assert_eq!(
                    body,
                    br#"{"error":"API specification fetch is busy; retry after the indicated delay"}"#
                );
                assert_eq!(
                    headers.get("content-type").map(String::as_str),
                    Some("application/json")
                );
                assert_eq!(
                    headers.get("content-length").map(String::as_str),
                    Some("76")
                );
                assert_eq!(headers.get("retry-after").map(String::as_str), Some("1"));
            }
            other => panic!("unexpected status {other}"),
        }
        assert!(headers.contains_key("retry-after"));
    }
    assert!(upstream_failures > 0);
    assert!(busy_rejections > 0, "excess waiters should fail quickly");

    // A request during the negative-cache window reuses the same failure and
    // does not generate another origin request.
    let mut cached_failure_ctx = make_ctx("GET", "/api/specz", "/api");
    let (status, _, headers) =
        reject_parts(plugin.on_request_received(&mut cached_failure_ctx).await);
    assert_eq!(status, 502);
    assert_eq!(headers.get("retry-after").map(String::as_str), Some("1"));
}

#[tokio::test(start_paused = true)]
async fn test_cached_failure_retry_after_reports_remaining_backoff() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/openapi.yaml"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
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

    let mut first_ctx = make_ctx("GET", "/api/specz", "/api");
    let (_, _, first_headers) = reject_parts(plugin.on_request_received(&mut first_ctx).await);
    assert_eq!(
        first_headers.get("retry-after").map(String::as_str),
        Some("1")
    );

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let mut second_ctx = make_ctx("GET", "/api/specz", "/api");
    let (_, _, second_headers) = reject_parts(plugin.on_request_received(&mut second_ctx).await);
    assert_eq!(
        second_headers.get("retry-after").map(String::as_str),
        Some("2")
    );

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let mut cached_ctx = make_ctx("GET", "/api/specz", "/api");
    let (_, _, cached_headers) = reject_parts(plugin.on_request_received(&mut cached_ctx).await);
    assert_eq!(
        cached_headers.get("retry-after").map(String::as_str),
        Some("1"),
        "cached failures must advertise only the remaining backoff"
    );
}

// TTL zero disables durable positive caching, but it must retain admission and
// single-flight coalescing so an anonymous burst cannot fan out to the origin.
#[tokio::test]
async fn test_ttl_zero_coalesces_concurrent_fetches() {
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
        // The six callers share one successful completion.
        .expect(1)
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
    // The single origin request takes 150ms; all waiters should reuse it rather
    // than serially issuing another five requests (~900ms).
    assert!(
        elapsed < std::time::Duration::from_millis(600),
        "TTL=0 concurrent fetches did not coalesce (took {elapsed:?}, expected <600ms)"
    );
}
