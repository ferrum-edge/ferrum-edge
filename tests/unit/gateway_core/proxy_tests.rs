use chrono::Utc;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::proxy::{build_backend_url, build_backend_url_with_target};
use ferrum_edge::router_cache::RouterCache;

fn test_proxy() -> Proxy {
    Proxy {
        id: "test".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("Test Proxy".into()),
        hosts: vec![],
        listen_path: Some("/api/v1".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "backend.example.com".into(),
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
        upstream_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_build_backend_url_strip() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/users/123",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/users/123");
}

#[test]
fn test_build_backend_url_no_strip() {
    let mut proxy = test_proxy();
    proxy.strip_listen_path = false;
    let url = build_backend_url(
        &proxy,
        "/api/v1/users/123",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/api/v1/users/123");
}

#[test]
fn test_build_backend_url_with_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/internal".into());
    let url = build_backend_url(
        &proxy,
        "/api/v1/users",
        "",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/internal/users");
}

#[test]
fn test_build_backend_url_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url(
        &proxy,
        "/api/v1/search",
        "q=hello&page=1",
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
    );
    assert_eq!(url, "http://backend.example.com:3000/search?q=hello&page=1");
}

#[test]
fn test_build_backend_url_target_path_overrides_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/v2"),
    );
    assert_eq!(url, "http://target.example.com:9090/v2/users");
}

#[test]
fn test_build_backend_url_target_path_none_uses_backend_path() {
    let mut proxy = test_proxy();
    proxy.backend_path = Some("/v1".into());
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        None,
    );
    assert_eq!(url, "http://target.example.com:9090/v1/users");
}

#[test]
fn test_build_backend_url_target_path_with_no_backend_path() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/users",
        "",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/service"),
    );
    assert_eq!(url, "http://target.example.com:9090/service/users");
}

#[test]
fn test_build_backend_url_target_path_with_query() {
    let proxy = test_proxy();
    let url = build_backend_url_with_target(
        &proxy,
        "/api/v1/search",
        "q=hello",
        "target.example.com",
        9090,
        proxy.listen_path.as_deref().map(str::len).unwrap_or(0),
        Some("/svc"),
    );
    assert_eq!(url, "http://target.example.com:9090/svc/search?q=hello");
}

#[test]
fn test_longest_prefix_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                listen_path: Some("/api".to_string()),
                id: "short".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                ..test_proxy()
            },
            Proxy {
                listen_path: Some("/api/v1".to_string()),
                id: "long".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                ..test_proxy()
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/api/v1/users");
    assert!(matched.is_some());
    assert_eq!(matched.unwrap().proxy.id, "long");
}

#[test]
fn test_no_match() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![Proxy {
            listen_path: Some("/api".to_string()),
            ..test_proxy()
        }],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
    };
    let router = RouterCache::new(&config, 10000);
    let matched = router.find_proxy(None, "/other/path");
    assert!(matched.is_none());
}

// ── Internal proxy/mod.rs function tests (moved from inline) ─────────────────

use async_trait::async_trait;
use ferrum_edge::_test_support::{
    apply_request_body_plugins, can_use_direct_http2_pool, extract_grpc_reject_message,
    insert_grpc_error_metadata, map_http_reject_status_to_grpc_status, normalize_reject_response,
    request_may_have_body,
};
use ferrum_edge::config::types::Consumer;
use ferrum_edge::consumer_index::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext, key_auth::KeyAuth};
use ferrum_edge::proxy::grpc_proxy::grpc_status;
use ferrum_edge::proxy::run_authentication_phase;
use hyper::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

struct ExternalIdentityAuth;

#[async_trait]
impl Plugin for ExternalIdentityAuth {
    fn name(&self) -> &str {
        "external_identity_auth"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        ctx.authenticated_identity = Some("external-user".to_string());
        ctx.authenticated_identity_header = Some("external@example.com".to_string());
        PluginResult::Continue
    }
}

struct RejectingAuth {
    body: &'static str,
}

#[async_trait]
impl Plugin for RejectingAuth {
    fn name(&self) -> &str {
        "rejecting_auth"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    async fn authenticate(
        &self,
        _ctx: &mut RequestContext,
        _consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        PluginResult::Reject {
            status_code: 401,
            body: self.body.to_string(),
            headers: HashMap::new(),
        }
    }
}

struct BodySuffixPlugin {
    suffix: &'static str,
}

#[async_trait]
impl Plugin for BodySuffixPlugin {
    fn name(&self) -> &str {
        "body_suffix"
    }
    fn modifies_request_body(&self) -> bool {
        true
    }
    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let mut out = body.to_vec();
        out.extend_from_slice(self.suffix.as_bytes());
        Some(out)
    }
}

#[tokio::test]
async fn test_multi_auth_accepts_external_identity_without_consumer() {
    let external: Arc<dyn Plugin> = Arc::new(ExternalIdentityAuth);
    let rejecting: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Missing credentials"}"#,
    });
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![external, rejecting];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    assert!(result.is_none());
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_single_auth_missing_credentials_rejects_before_backend() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, headers) = result.expect("missing credentials should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_all_missing_credentials_rejects_before_backend() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let rejecting: Arc<dyn Plugin> = Arc::new(
        KeyAuth::new(&json!({
            "key_location": "query:api_key"
        }))
        .unwrap(),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![key_auth, rejecting];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, headers) = result.expect("all-missing multi-auth should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn test_multi_auth_preserves_specific_reject_when_surrounded_by_missing() {
    let missing_header: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let specific_reject: Arc<dyn Plugin> = Arc::new(RejectingAuth {
        body: r#"{"error":"Specific auth failure"}"#,
    });
    let missing_query: Arc<dyn Plugin> = Arc::new(
        KeyAuth::new(&json!({
            "key_location": "query:api_key"
        }))
        .unwrap(),
    );
    let auth_plugins: Vec<Arc<dyn Plugin>> = vec![missing_header, specific_reject, missing_query];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/key-auth".to_string(),
    );

    let result =
        run_authentication_phase(AuthMode::Multi, &auth_plugins, &mut ctx, &consumer_index).await;

    let (status_code, body, _headers) =
        result.expect("specific reject should win over generic missing fallback");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Specific auth failure"}"#);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

#[test]
fn test_request_context_effective_identity_prefers_consumer_then_external_identity() {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );
    assert_eq!(ctx.effective_identity(), None);

    ctx.authenticated_identity = Some("external-user".to_string());
    assert_eq!(ctx.effective_identity(), Some("external-user"));

    ctx.identified_consumer = Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "mapped-consumer".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    assert_eq!(ctx.effective_identity(), Some("mapped-consumer"));
}

#[test]
fn test_request_context_backend_consumer_username_prefers_consumer_then_header_then_identity() {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/jwks".to_string(),
    );
    assert_eq!(ctx.backend_consumer_username(), None);

    ctx.authenticated_identity = Some("external-user".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("external-user"));

    ctx.authenticated_identity_header = Some("user@example.com".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("user@example.com"));

    ctx.identified_consumer = Some(Arc::new(Consumer {
        id: "consumer-1".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "mapped-consumer".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }));
    assert_eq!(ctx.backend_consumer_username(), Some("mapped-consumer"));
    assert_eq!(ctx.backend_consumer_custom_id(), Some("custom-123"));
}

#[test]
fn test_map_http_reject_status_to_grpc_status_uses_semantic_codes() {
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::UNAUTHORIZED),
        grpc_status::UNAUTHENTICATED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::FORBIDDEN),
        grpc_status::PERMISSION_DENIED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::TOO_MANY_REQUESTS),
        grpc_status::RESOURCE_EXHAUSTED
    );
    assert_eq!(
        map_http_reject_status_to_grpc_status(StatusCode::BAD_GATEWAY),
        grpc_status::UNAVAILABLE
    );
}

#[test]
fn test_extract_grpc_reject_message_prefers_json_error_fields() {
    let body = br#"{"error":"Rate limit exceeded","details":"retry later"}"#;
    assert_eq!(
        extract_grpc_reject_message(body).as_deref(),
        Some("Rate limit exceeded")
    );
}

#[test]
fn test_normalize_reject_response_converts_grpc_requests_to_trailers_only_errors() {
    let mut headers = HashMap::new();
    headers.insert("x-ratelimit-limit".to_string(), "5".to_string());

    let normalized = normalize_reject_response(
        StatusCode::TOO_MANY_REQUESTS,
        br#"{"error":"Rate limit exceeded"}"#,
        &headers,
        true,
    );

    assert_eq!(normalized.http_status, StatusCode::OK);
    assert!(normalized.body.is_empty());
    assert_eq!(
        normalized.grpc_status,
        Some(grpc_status::RESOURCE_EXHAUSTED)
    );
    assert_eq!(
        normalized.grpc_message.as_deref(),
        Some("Rate limit exceeded")
    );
    assert_eq!(
        normalized.headers.get("content-type").map(|s| s.as_str()),
        Some("application/grpc")
    );
    assert_eq!(
        normalized.headers.get("grpc-status").map(|s| s.as_str()),
        Some("8")
    );
    assert_eq!(
        normalized
            .headers
            .get("x-ratelimit-limit")
            .map(|s| s.as_str()),
        Some("5")
    );
}

#[test]
fn test_insert_grpc_error_metadata_sanitizes_message() {
    let mut metadata = HashMap::new();
    insert_grpc_error_metadata(
        &mut metadata,
        grpc_status::UNAVAILABLE,
        "backend unavailable\nretry later",
    );
    assert_eq!(metadata.get("grpc_status").map(|s| s.as_str()), Some("14"));
    assert_eq!(
        metadata.get("grpc_message").map(|s| s.as_str()),
        Some("backend unavailable retry later")
    );
}

#[test]
fn test_direct_http2_pool_requires_http2_without_retries_or_request_buffering() {
    assert!(can_use_direct_http2_pool(true, false, false));
    assert!(!can_use_direct_http2_pool(false, false, false));
    assert!(!can_use_direct_http2_pool(true, true, false));
    assert!(!can_use_direct_http2_pool(true, false, true));
}

#[test]
fn test_request_may_have_body_uses_method_and_body_headers() {
    let no_headers = HashMap::new();
    assert!(!request_may_have_body("GET", &no_headers));
    assert!(request_may_have_body("POST", &no_headers));
    assert!(request_may_have_body(
        "GET",
        &HashMap::from([("content-length".to_string(), "0".to_string())])
    ));
}

#[tokio::test]
async fn test_apply_request_body_plugins_preserves_plugin_order() {
    let first: Arc<dyn Plugin> = Arc::new(BodySuffixPlugin { suffix: "-first" });
    let second: Arc<dyn Plugin> = Arc::new(BodySuffixPlugin { suffix: "-second" });
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);
    let transformed =
        apply_request_body_plugins(&[first, second], &headers, b"body".to_vec()).await;
    assert_eq!(transformed, b"body-first-second");
}
