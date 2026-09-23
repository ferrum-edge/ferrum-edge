use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use ferrum_edge::_test_support::{
    canonical_header_content_length_from_map_for_test, coalesce_flush_window_for_test,
    preserved_response_content_length_for_test, run_after_proxy_hooks_for_test,
    should_bypass_h2_coalesce_for_large_response_for_test,
    streaming_response_requires_size_limit_for_test,
    streaming_response_takes_direct_fast_path_for_test,
};
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, Proxy, ResponseBodyMode};
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};

fn test_proxy() -> Proxy {
    Proxy {
        labels: Default::default(),
        id: "test".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Test Proxy".into()),
        hosts: vec![],
        listen_path: Some("/api".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".into(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

// --- ResponseBodyMode config tests ---

#[test]
fn test_response_body_mode_defaults_to_stream() {
    let proxy = test_proxy();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Stream);
}

#[test]
fn test_response_body_mode_default_impl() {
    assert_eq!(ResponseBodyMode::default(), ResponseBodyMode::Stream);
}

#[test]
fn test_response_body_mode_buffer_variant() {
    let mut proxy = test_proxy();
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Buffer);
}

#[test]
fn test_response_body_mode_serde_stream() {
    let json = r#""stream""#;
    let mode: ResponseBodyMode = serde_json::from_str(json).unwrap();
    assert_eq!(mode, ResponseBodyMode::Stream);
}

#[test]
fn test_response_body_mode_serde_buffer() {
    let json = r#""buffer""#;
    let mode: ResponseBodyMode = serde_json::from_str(json).unwrap();
    assert_eq!(mode, ResponseBodyMode::Buffer);
}

#[test]
fn test_response_body_mode_serde_roundtrip() {
    for mode in [ResponseBodyMode::Stream, ResponseBodyMode::Buffer] {
        let json = serde_json::to_string(&mode).unwrap();
        let deserialized: ResponseBodyMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, deserialized);
    }
}

#[test]
fn test_proxy_yaml_default_response_body_mode() {
    let yaml = r#"
        id: test
        listen_path: /api
        backend_scheme: http
        backend_host: localhost
        backend_port: 3000
    "#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Stream);
}

#[test]
fn test_proxy_yaml_buffer_response_body_mode() {
    let yaml = r#"
        id: test
        listen_path: /api
        backend_scheme: http
        backend_host: localhost
        backend_port: 3000
        response_body_mode: buffer
    "#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Buffer);
}

#[test]
fn test_proxy_yaml_stream_response_body_mode() {
    let yaml = r#"
        id: test
        listen_path: /api
        backend_scheme: http
        backend_host: localhost
        backend_port: 3000
        response_body_mode: stream
    "#;
    let proxy: Proxy = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(proxy.response_body_mode, ResponseBodyMode::Stream);
}

// --- Plugin requires_response_body_buffering tests ---

#[test]
fn test_plugin_default_does_not_require_buffering() {
    use async_trait::async_trait;
    use ferrum_edge::plugins::Plugin;

    struct TestPlugin;

    #[async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &str {
            "test_plugin"
        }
    }

    let plugin = TestPlugin;
    assert!(!plugin.requires_response_body_buffering());
}

#[test]
fn test_plugin_can_require_buffering() {
    use async_trait::async_trait;
    use ferrum_edge::plugins::Plugin;

    struct BufferingPlugin;

    #[async_trait]
    impl Plugin for BufferingPlugin {
        fn name(&self) -> &str {
            "buffering_plugin"
        }

        fn requires_response_body_buffering(&self) -> bool {
            true
        }
    }

    let plugin = BufferingPlugin;
    assert!(plugin.requires_response_body_buffering());
}

// --- ResponseBody enum tests ---

#[test]
fn test_response_body_buffered() {
    use ferrum_edge::retry::ResponseBody;

    let body = ResponseBody::buffered(b"hello".to_vec());
    match body {
        ResponseBody::Buffered(data) => assert_eq!(&data[..], b"hello"),
        _ => panic!("Expected Buffered variant"),
    }
}

// --- Streaming mode determination logic tests ---

#[test]
fn test_streaming_mode_with_buffer_config() {
    let mut proxy = test_proxy();
    proxy.response_body_mode = ResponseBodyMode::Buffer;
    let should_stream = matches!(proxy.response_body_mode, ResponseBodyMode::Stream);
    assert!(!should_stream);
}

#[test]
fn test_streaming_mode_with_stream_config_no_plugins() {
    let proxy = test_proxy();
    let plugins: Vec<&dyn ferrum_edge::plugins::Plugin> = vec![];
    let plugin_requires_buffering = plugins.iter().any(|p| p.requires_response_body_buffering());
    let should_stream =
        matches!(proxy.response_body_mode, ResponseBodyMode::Stream) && !plugin_requires_buffering;
    assert!(should_stream);
}

// --- Issue #4279: size-limit enforcement uses trusted backend length --------

struct InsertContentLength {
    value: &'static str,
}

#[async_trait::async_trait]
impl Plugin for InsertContentLength {
    fn name(&self) -> &str {
        "insert_content_length"
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert("content-length".to_string(), self.value.to_string());
        PluginResult::Continue
    }
}

struct RewriteContentLength {
    value: &'static str,
}

#[async_trait::async_trait]
impl Plugin for RewriteContentLength {
    fn name(&self) -> &str {
        "rewrite_content_length"
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // HashMap keys are case-sensitive. A rewrite must drop every
        // Content-Length case variant first; inserting `"Content-Length"`
        // beside an existing `"content-length"` leaves two fields, and
        // `preserved_response_content_length` fail-closes to None (the
        // wire/completeness contract, not a successful rewrite).
        response_headers.retain(|name, _| !name.eq_ignore_ascii_case("content-length"));
        response_headers.insert("Content-Length".to_string(), self.value.to_string());
        PluginResult::Continue
    }
}

fn size_limit_ctx() -> RequestContext {
    RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/stream".to_string(),
    )
}

/// A backend response with no Content-Length plus an `after_proxy` hook that
/// inserts one must still select the size-limited streaming adapter.
#[tokio::test]
async fn inserted_content_length_cannot_suppress_size_limited_streaming_adapter() {
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".into(),
    )]);
    let trusted = canonical_header_content_length_from_map_for_test(&headers);
    assert_eq!(trusted, None, "backend did not declare a length");

    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(InsertContentLength { value: "1048576" })];
    let mut ctx = size_limit_ctx();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await);

    let declared = preserved_response_content_length_for_test(&headers, 200);
    assert_eq!(
        declared,
        Some(1_048_576),
        "the hook-authored length is visible for wire/completeness consumers"
    );
    assert!(
        streaming_response_requires_size_limit_for_test(64, trusted),
        "trusted None must still wrap the size-limited adapter"
    );
    assert!(
        !streaming_response_requires_size_limit_for_test(64, declared),
        "using the post-hook length would skip the adapter — that is the bug"
    );
}

/// Rewriting Content-Length to a large value must not select the direct-H2
/// passthrough that skips both coalescing and size-limit enforcement.
#[tokio::test]
async fn rewritten_content_length_cannot_select_h2_passthrough() {
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".into(),
    )]);
    let trusted = canonical_header_content_length_from_map_for_test(&headers);
    assert_eq!(trusted, None);

    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RewriteContentLength { value: "1048576" })];
    let mut ctx = size_limit_ctx();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await);

    let declared = preserved_response_content_length_for_test(&headers, 200);
    let max = 10 * 1024 * 1024;
    assert!(
        !should_bypass_h2_coalesce_for_large_response_for_test(trusted, max),
        "unknown-length backend must not passthrough"
    );
    assert!(
        should_bypass_h2_coalesce_for_large_response_for_test(declared, max),
        "using the inserted 1 MiB length would wrongly passthrough — that is the bug"
    );
    assert!(streaming_response_requires_size_limit_for_test(
        max, trusted
    ));
}

/// A genuine backend Content-Length within the cap still skips the
/// size-limited adapter (the pre-commit check already admitted it).
#[test]
fn trusted_backend_content_length_within_limit_skips_size_limited_adapter() {
    let headers = HashMap::from([("content-length".to_string(), "100".to_string())]);
    let trusted = canonical_header_content_length_from_map_for_test(&headers);
    assert_eq!(trusted, Some(100));
    assert!(!streaming_response_requires_size_limit_for_test(
        64 * 1024,
        trusted,
    ));
    assert!(streaming_response_requires_size_limit_for_test(
        64 * 1024,
        None
    ));
}

/// Conflicting folded Content-Length values are unusable, not a trusted
/// length: the HashMap parser must fail closed so the streaming adapter still
/// wraps (matching the HeaderMap pre-commit path, which also returns None).
#[test]
fn conflicting_backend_content_length_still_requires_size_limited_adapter() {
    let headers = HashMap::from([("content-length".to_string(), "100, 200".to_string())]);
    let trusted = canonical_header_content_length_from_map_for_test(&headers);
    assert_eq!(
        trusted, None,
        "ambiguous backend length must not be treated as Exact"
    );
    assert!(streaming_response_requires_size_limit_for_test(
        64 * 1024,
        trusted
    ));
}

/// Rewriting an existing small backend Content-Length to a large value must
/// not select the direct-H2 passthrough: passthrough is keyed on the trusted
/// backend length, not the post-hook map.
#[tokio::test]
async fn rewritten_small_backend_content_length_cannot_select_h2_passthrough() {
    let mut headers = HashMap::from([("content-length".to_string(), "100".to_string())]);
    let trusted = canonical_header_content_length_from_map_for_test(&headers);
    assert_eq!(trusted, Some(100));

    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(RewriteContentLength { value: "1048576" })];
    let mut ctx = size_limit_ctx();
    assert!(!run_after_proxy_hooks_for_test(&plugins, &mut ctx, 200, &mut headers).await);

    let declared = preserved_response_content_length_for_test(&headers, 200);
    assert_eq!(declared, Some(1_048_576));
    let max = 10 * 1024 * 1024;
    assert!(
        !should_bypass_h2_coalesce_for_large_response_for_test(trusted, max),
        "trusted 100-byte length must not passthrough"
    );
    assert!(
        should_bypass_h2_coalesce_for_large_response_for_test(declared, max),
        "using the rewritten 1 MiB length would wrongly passthrough — that is the bug"
    );
    assert!(!streaming_response_requires_size_limit_for_test(
        max, trusted
    ));
}

/// Issue #5588. The window must stay well inside the idle read deadline: with
/// one configured the coalescer parks holding a sub-target frame, and
/// `IdleReadTimeoutBody` would otherwise read that as a stalled backend.
#[test]
fn coalesce_flush_window_is_clamped_to_half_the_idle_read_timeout() {
    use std::time::Duration;

    // Disabled is the shipped default and survives any timeout.
    assert_eq!(coalesce_flush_window_for_test(0, 5_000), None);
    assert_eq!(coalesce_flush_window_for_test(0, 0), None);

    // Comfortably inside the deadline: taken as configured.
    assert_eq!(
        coalesce_flush_window_for_test(2, 5_000),
        Some(Duration::from_millis(2))
    );

    // At or past half the deadline: clamped, never adopted whole.
    assert_eq!(
        coalesce_flush_window_for_test(1_000, 100),
        Some(Duration::from_millis(50))
    );
    assert_eq!(
        coalesce_flush_window_for_test(60, 100),
        Some(Duration::from_millis(50))
    );

    // No timeout configured means no deadline to protect.
    assert_eq!(
        coalesce_flush_window_for_test(1_000, 0),
        Some(Duration::from_millis(1_000))
    );
}

/// Issue #5588 regression guard. In the shipped default configuration the
/// fast path skips the coalescing adapter entirely, so a window that did not
/// count as a reason to coalesce would be silently inert — which it was.
#[test]
fn a_configured_flush_window_keeps_the_body_off_the_direct_fast_path() {
    use std::time::Duration;

    let takes_fast_path = streaming_response_takes_direct_fast_path_for_test;
    let window = Some(Duration::from_millis(2));

    // Shipped default: cutoff disabled, no size limit, no window. The fast
    // path is the whole point here — nothing needs per-frame buffering.
    assert!(takes_fast_path(0, 0, None));

    // In exactly that default configuration, a window is the ONLY thing asking
    // for aggregation, so it alone must keep the body on the coalescing path.
    assert!(!takes_fast_path(0, 0, window));

    // The pre-existing reasons to coalesce still hold on their own, with or
    // without a window.
    assert!(!takes_fast_path(1, 0, None));
    assert!(!takes_fast_path(0, 1, None));
    assert!(!takes_fast_path(1, 1, window));
}
