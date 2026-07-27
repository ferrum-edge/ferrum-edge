use std::collections::HashMap;

use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, Consumer, DispatchKind, GatewayConfig, HttpFlavor, PluginAssociation,
    PluginConfig, PluginScope, Proxy,
};
use ferrum_edge::plugins::{ProxyProtocol, RequestContext};
use ferrum_edge::proxy::backend_dispatch::detect_http_flavor;
use ferrum_edge::proxy::run_authentication_phase;
use ferrum_edge::{ConsumerIndex, PluginCache, PluginCapabilities};
use http::Request;
use serde_json::{Map, Value, json};

const PROXY_ID: &str = "ws-secured-proxy";
const PLUGIN_ID: &str = "plugin-keyauth-ws";
const VALID_API_KEY: &str = "ws-valid-api-key-112233";

fn keyauth_proxy() -> Proxy {
    Proxy {
        id: PROXY_ID.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("WebSocket secured proxy".to_string()),
        hosts: vec![],
        listen_path: Some("/ws-secure".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 19090,
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
        plugins: vec![PluginAssociation {
            plugin_config_id: PLUGIN_ID.to_string(),
        }],
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
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn keyauth_plugin_config() -> PluginConfig {
    PluginConfig {
        id: PLUGIN_ID.to_string(),
        plugin_name: "key_auth".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({"key_location": "header:x-api-key"}),
        scope: PluginScope::Proxy,
        proxy_id: Some(PROXY_ID.to_string()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn keyauth_consumer() -> Consumer {
    let mut keyauth_creds = Map::new();
    keyauth_creds.insert("key".to_string(), Value::String(VALID_API_KEY.to_string()));

    let mut credentials = HashMap::new();
    credentials.insert(
        "keyauth".to_string(),
        Value::Array(vec![Value::Object(keyauth_creds)]),
    );

    Consumer {
        id: "consumer-ws-client".to_string(),
        username: "ws-test-client".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        custom_id: Some("ws-custom-id".to_string()),
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn gateway_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![keyauth_proxy()],
        consumers: vec![keyauth_consumer()],
        plugin_configs: vec![keyauth_plugin_config()],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn websocket_upgrade_request(api_key: Option<&str>) -> Request<()> {
    let mut request = Request::builder()
        .method("GET")
        .version(hyper::Version::HTTP_11)
        .uri("/ws-secure?room=blue")
        .header("host", "gateway.example")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .header("sec-websocket-version", "13")
        .body(())
        .unwrap();

    if let Some(api_key) = api_key {
        request
            .headers_mut()
            .insert("x-api-key", api_key.parse().unwrap());
    }

    request
}

fn websocket_request_context(api_key: Option<&str>) -> RequestContext {
    let request = websocket_upgrade_request(api_key);
    assert_eq!(detect_http_flavor(&request), HttpFlavor::WebSocket);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        request.method().as_str().to_string(),
        request.uri().path().to_string(),
    );
    ctx.set_raw_headers(request.headers().clone());
    ctx.set_raw_query_string(request.uri().query().unwrap_or("").to_string());
    ctx.materialize_headers();
    ctx.materialize_query_params();
    ctx
}

#[test]
fn websocket_upgrade_uses_websocket_protocol_for_auth_plugin_lookup() {
    let config = gateway_config();
    let cache = PluginCache::new(&config).expect("plugin cache");
    let request = websocket_upgrade_request(None);

    assert_eq!(detect_http_flavor(&request), HttpFlavor::WebSocket);

    let ws_view = cache.request_view("ferrum", PROXY_ID, ProxyProtocol::WebSocket);
    let auth_plugins = ws_view.auth_plugins();
    assert_eq!(auth_plugins.len(), 1);
    assert_eq!(auth_plugins[0].name(), "key_auth");
    assert!(
        ws_view
            .capabilities()
            .has(PluginCapabilities::HAS_AUTH_PLUGINS)
    );

    let tcp_view = cache.request_view("ferrum", PROXY_ID, ProxyProtocol::Tcp);
    assert!(
        tcp_view.auth_plugins().is_empty(),
        "HTTP-family key_auth must not leak into TCP, while WebSocket still gets it"
    );
}

#[tokio::test]
async fn websocket_upgrade_without_api_key_rejects_before_backend() {
    let config = gateway_config();
    let cache = PluginCache::new(&config).expect("plugin cache");
    let auth_plugins = cache
        .request_view("ferrum", PROXY_ID, ProxyProtocol::WebSocket)
        .auth_plugins();
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let mut ctx = websocket_request_context(None);

    let result = run_authentication_phase(
        AuthMode::Single,
        auth_plugins.as_slice(),
        &mut ctx,
        &consumer_index,
    )
    .await;

    let (status_code, body, headers) = result.expect("missing key should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Authentication required"}"#);
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.auth_method.is_none());
}

#[tokio::test]
async fn websocket_upgrade_with_invalid_api_key_preserves_plugin_reject() {
    let config = gateway_config();
    let cache = PluginCache::new(&config).expect("plugin cache");
    let auth_plugins = cache
        .request_view("ferrum", PROXY_ID, ProxyProtocol::WebSocket)
        .auth_plugins();
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let mut ctx = websocket_request_context(Some("wrong-key"));

    let result = run_authentication_phase(
        AuthMode::Single,
        auth_plugins.as_slice(),
        &mut ctx,
        &consumer_index,
    )
    .await;

    let (status_code, body, headers) = result.expect("invalid key should reject");
    assert_eq!(status_code, 401);
    assert_eq!(body, br#"{"error":"Invalid API key"}"#);
    assert!(headers.is_empty());
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.auth_method.is_none());
}

#[tokio::test]
async fn websocket_upgrade_with_valid_api_key_identifies_consumer() {
    let config = gateway_config();
    let cache = PluginCache::new(&config).expect("plugin cache");
    let auth_plugins = cache
        .request_view("ferrum", PROXY_ID, ProxyProtocol::WebSocket)
        .auth_plugins();
    let consumer_index = ConsumerIndex::new(&config.consumers);
    let mut ctx = websocket_request_context(Some(VALID_API_KEY));

    let result = run_authentication_phase(
        AuthMode::Single,
        auth_plugins.as_slice(),
        &mut ctx,
        &consumer_index,
    )
    .await;

    assert!(result.is_none());
    let consumer = ctx
        .identified_consumer
        .as_ref()
        .expect("valid key should identify a consumer");
    assert_eq!(consumer.username, "ws-test-client");
    assert_eq!(ctx.auth_method, Some("key_auth"));
    assert_eq!(ctx.effective_identity(), Some("ws-test-client"));
}
