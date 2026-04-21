//! Tests for plugin protocol support declarations.
//!
//! Verifies that each plugin correctly declares which proxy protocols
//! it supports via the `supported_protocols()` trait method.

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, HTTP_FAMILY_AND_STREAM_PROTOCOLS, HTTP_FAMILY_PROTOCOLS, HTTP_GRPC_PROTOCOLS,
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, StreamConnectionContext,
    StreamTransactionSummary, TCP_ONLY_PROTOCOLS, create_plugin,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// Helper to create a plugin by name with minimal config.
fn make_plugin(name: &str, config: serde_json::Value) -> Option<Arc<dyn Plugin>> {
    create_plugin(name, &config).ok().flatten()
}

fn empty_consumer_index() -> Arc<ferrum_edge::ConsumerIndex> {
    Arc::new(ferrum_edge::ConsumerIndex::new(&[]))
}

fn test_consumer(username: &str) -> ferrum_edge::config::types::Consumer {
    ferrum_edge::config::types::Consumer {
        id: format!("consumer-{username}"),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn test_all_protocol_plugins() {
    // Plugins that support ALL protocols (protocol-agnostic)
    let plugins = vec![
        ("ip_restriction", json!({"allow": ["10.0.0.0/8"]})),
        (
            "rate_limiting",
            json!({"window_seconds": 60, "max_requests": 100}),
        ),
        ("stdout_logging", json!({})),
        ("prometheus_metrics", json!({})),
        ("correlation_id", json!({})),
        (
            "otel_tracing",
            json!({"endpoint": "http://example.com/traces"}),
        ),
        (
            "http_logging",
            json!({"endpoint_url": "http://example.com/logs"}),
        ),
        ("transaction_debugger", json!({})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, ALL_PROTOCOLS,
            "Plugin {} should support all protocols, got {:?}",
            name, protocols
        );
    }
}

#[test]
fn test_http_family_plugins() {
    // Plugins that support HTTP, gRPC, and WebSocket
    let plugins = vec![
        ("key_auth", json!({})),
        ("basic_auth", json!({})),
        ("bot_detection", json!({})),
        ("request_termination", json!({"status_code": 503})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_FAMILY_PROTOCOLS,
            "Plugin {} should support HTTP family protocols, got {:?}",
            name, protocols
        );
        // Verify it does NOT support TCP/UDP
        assert!(
            !protocols.contains(&ProxyProtocol::Tcp),
            "Plugin {} should not support TCP",
            name
        );
        assert!(
            !protocols.contains(&ProxyProtocol::Udp),
            "Plugin {} should not support UDP",
            name
        );
    }
}

#[test]
fn test_http_family_and_stream_plugins() {
    // mtls_auth and access_control support all stream transports (TCP + UDP/DTLS)
    let plugins = vec![
        ("mtls_auth", json!({})),
        ("access_control", json!({"allowed_consumers": ["admin"]})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_FAMILY_AND_STREAM_PROTOCOLS,
            "Plugin {} should support HTTP_FAMILY_AND_STREAM_PROTOCOLS, got {:?}",
            name, protocols
        );
        assert!(
            protocols.contains(&ProxyProtocol::Tcp),
            "Plugin {} should support TCP",
            name
        );
        assert!(
            protocols.contains(&ProxyProtocol::Udp),
            "Plugin {} should support UDP/DTLS",
            name
        );
    }
}

#[test]
fn test_http_grpc_plugins() {
    // Plugins that support HTTP and gRPC only (modify headers/body)
    let plugins = vec![
        (
            "request_transformer",
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]}),
        ),
        (
            "response_transformer",
            json!({"rules": [{"operation": "add", "key": "x-test", "value": "1"}]}),
        ),
        ("body_validator", json!({"required_fields": ["name"]})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_GRPC_PROTOCOLS,
            "Plugin {} should support HTTP+gRPC only, got {:?}",
            name, protocols
        );
        assert!(
            !protocols.contains(&ProxyProtocol::WebSocket),
            "Plugin {} should not support WebSocket",
            name
        );
    }
}

#[test]
fn test_http_only_plugins() {
    // Plugins that only support HTTP
    let plugins = vec![("cors", json!({"origins": ["*"]}))];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols, HTTP_ONLY_PROTOCOLS,
            "Plugin {} should support HTTP only, got {:?}",
            name, protocols
        );
    }
}

#[test]
fn test_stream_compatible_plugins_support_tcp_udp() {
    // Verify that stream-compatible plugins support both TCP and UDP
    let stream_plugins = vec![
        ("ip_restriction", json!({"allow": ["10.0.0.0/8"]})),
        (
            "rate_limiting",
            json!({"window_seconds": 60, "max_requests": 100}),
        ),
        ("stdout_logging", json!({})),
        ("prometheus_metrics", json!({})),
        ("correlation_id", json!({})),
    ];

    for (name, config) in stream_plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert!(
            protocols.contains(&ProxyProtocol::Tcp),
            "Plugin {} should support TCP",
            name
        );
        assert!(
            protocols.contains(&ProxyProtocol::Udp),
            "Plugin {} should support UDP",
            name
        );
    }
}

#[test]
fn test_tcp_only_plugins() {
    let plugin = make_plugin(
        "tcp_connection_throttle",
        json!({"max_connections_per_key": 10}),
    )
    .unwrap();

    assert_eq!(plugin.supported_protocols(), TCP_ONLY_PROTOCOLS);
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Tcp));
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Udp));
}

#[tokio::test]
async fn test_ip_restriction_stream_connect_allowed() {
    let plugin = make_plugin(
        "ip_restriction",
        json!({"allow": ["10.0.0.0/8"], "mode": "allow_first"}),
    )
    .unwrap();

    let mut ctx = StreamConnectionContext {
        client_ip: "10.1.2.3".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: empty_consumer_index(),
        identified_consumer: None,
        authenticated_identity: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
    };

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_ip_restriction_stream_connect_denied() {
    let plugin = make_plugin(
        "ip_restriction",
        json!({"allow": ["10.0.0.0/8"], "mode": "allow_first"}),
    )
    .unwrap();

    let mut ctx = StreamConnectionContext {
        client_ip: "192.168.1.1".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: empty_consumer_index(),
        identified_consumer: None,
        authenticated_identity: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
    };

    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
}

// ---- Stream hook behavior tests ----

fn make_stream_ctx() -> StreamConnectionContext {
    StreamConnectionContext {
        client_ip: "10.1.2.3".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        listen_port: 5432,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: empty_consumer_index(),
        identified_consumer: None,
        authenticated_identity: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
    }
}

fn make_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: Some("Test Proxy".to_string()),
        client_ip: "10.1.2.3".to_string(),
        consumer_username: None,
        backend_target: "10.0.0.50:5432".to_string(),
        backend_resolved_ip: Some("10.0.0.50".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 5432,
        duration_ms: 1500.0,
        bytes_sent: 2048,
        bytes_received: 4096,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2026-03-29T12:00:00Z".to_string(),
        timestamp_disconnected: "2026-03-29T12:00:01.5Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_rate_limiting_stream_connect_allowed() {
    let plugin = make_plugin("rate_limiting", json!({"requests_per_second": 100})).unwrap();
    let mut ctx = make_stream_ctx();
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_rate_limiting_stream_connect_rejected() {
    let plugin = make_plugin("rate_limiting", json!({"requests_per_second": 1})).unwrap();

    let mut ctx1 = make_stream_ctx();
    let result1 = plugin.on_stream_connect(&mut ctx1).await;
    assert!(matches!(result1, PluginResult::Continue));

    // Second connection from same IP should be rate limited
    let mut ctx2 = make_stream_ctx();
    let result2 = plugin.on_stream_connect(&mut ctx2).await;
    assert!(
        matches!(
            result2,
            PluginResult::Reject {
                status_code: 429,
                ..
            }
        ),
        "Second stream connection should be rate limited"
    );
}

#[tokio::test]
async fn test_rate_limiting_stream_connect_consumer_mode_uses_consumer_identity() {
    let plugin = make_plugin(
        "rate_limiting",
        json!({"requests_per_second": 1, "limit_by": "consumer"}),
    )
    .unwrap();

    let mut ctx1 = make_stream_ctx();
    ctx1.client_ip = "10.0.0.1".to_string();
    ctx1.identified_consumer = Some(Arc::new(test_consumer("alice")));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));

    let mut ctx2 = make_stream_ctx();
    ctx2.client_ip = "10.0.0.2".to_string();
    ctx2.identified_consumer = Some(Arc::new(test_consumer("alice")));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));

    let mut ctx3 = make_stream_ctx();
    ctx3.client_ip = "10.0.0.3".to_string();
    ctx3.identified_consumer = Some(Arc::new(test_consumer("bob")));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx3).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_correlation_id_stream_connect_assigns_id() {
    let plugin = make_plugin("correlation_id", json!({})).unwrap();
    let mut ctx = make_stream_ctx();
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let meta = ctx.metadata.as_ref().expect("metadata should be allocated");
    assert!(
        meta.contains_key("request_id"),
        "correlation_id should insert request_id into metadata"
    );
    assert!(
        !meta["request_id"].is_empty(),
        "request_id should not be empty"
    );
}

#[tokio::test]
async fn test_otel_tracing_stream_connect_assigns_trace_id() {
    let plugin = make_plugin(
        "otel_tracing",
        json!({"endpoint": "http://example.com/traces"}),
    )
    .unwrap();
    let mut ctx = make_stream_ctx();
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let meta = ctx.metadata.as_ref().expect("metadata should be allocated");
    assert!(
        meta.contains_key("trace_id"),
        "otel_tracing should insert trace_id"
    );
    assert!(
        meta.contains_key("span_id"),
        "otel_tracing should insert span_id"
    );
    assert!(!meta["trace_id"].is_empty());
    assert!(!meta["span_id"].is_empty());
}

#[tokio::test]
async fn test_stdout_logging_stream_disconnect_no_panic() {
    let plugin = make_plugin("stdout_logging", json!({})).unwrap();
    let summary = make_stream_summary();
    plugin.on_stream_disconnect(&summary).await;
    // Smoke test — no panic means it works
}

#[tokio::test]
async fn test_transaction_debugger_stream_disconnect_no_panic() {
    let plugin = make_plugin("transaction_debugger", json!({})).unwrap();
    let summary = make_stream_summary();
    plugin.on_stream_disconnect(&summary).await;
}

#[tokio::test]
async fn test_prometheus_metrics_stream_disconnect_records() {
    let plugin = make_plugin("prometheus_metrics", json!({})).unwrap();
    let summary = make_stream_summary();
    plugin.on_stream_disconnect(&summary).await;

    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let output = registry.render();
    assert!(
        output.contains("ferrum_stream_connections_total"),
        "Prometheus should record stream connections after on_stream_disconnect"
    );
}

#[tokio::test]
async fn test_stream_metadata_flows_from_connect_to_disconnect() {
    // Correlation ID assigns request_id in on_stream_connect
    let plugin = make_plugin("correlation_id", json!({})).unwrap();
    let mut ctx = make_stream_ctx();
    plugin.on_stream_connect(&mut ctx).await;
    let meta = ctx.metadata.as_ref().expect("metadata should be allocated");
    let request_id = meta.get("request_id").cloned().unwrap();

    // Build disconnect summary with the metadata from connect
    let mut summary = make_stream_summary();
    summary.metadata = ctx.take_metadata();
    assert_eq!(
        summary.metadata.get("request_id").unwrap(),
        &request_id,
        "Metadata should flow from connect to disconnect summary"
    );
}

// ---- WebSocket-only frame plugins ----

#[test]
fn test_ws_only_plugins() {
    let plugins = vec![
        ("ws_message_size_limiting", json!({"max_frame_bytes": 1024})),
        ("ws_frame_logging", json!({})),
        ("ws_rate_limiting", json!({"frames_per_second": 100})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        let protocols = plugin.supported_protocols();
        assert_eq!(
            protocols.len(),
            1,
            "Plugin {} should support exactly 1 protocol (WebSocket), got {:?}",
            name,
            protocols
        );
        assert!(
            protocols.contains(&ProxyProtocol::WebSocket),
            "Plugin {} must support WebSocket",
            name
        );
        assert!(
            !protocols.contains(&ProxyProtocol::Http),
            "Plugin {} must NOT support HTTP",
            name
        );
        assert!(
            !protocols.contains(&ProxyProtocol::Grpc),
            "Plugin {} must NOT support gRPC",
            name
        );
        assert!(
            !protocols.contains(&ProxyProtocol::Tcp),
            "Plugin {} must NOT support TCP",
            name
        );
        assert!(
            !protocols.contains(&ProxyProtocol::Udp),
            "Plugin {} must NOT support UDP",
            name
        );
        // All WS frame plugins must opt into frame hooks
        assert!(
            plugin.requires_ws_frame_hooks(),
            "Plugin {} must return true from requires_ws_frame_hooks()",
            name
        );
    }
}

// ---- Complete protocol declaration coverage for ALL plugins ----

#[tokio::test]
async fn test_http_family_plugins_complete_coverage() {
    // Plugins missing from the base test: hmac_auth, jwks_auth, jwt_auth
    let plugins = vec![
        ("hmac_auth", json!({})),
        (
            "jwks_auth",
            json!({"providers": [{"issuer": "test", "jwks_uri": "http://example.com/.well-known/jwks.json"}]}),
        ),
        (
            "jwt_auth",
            json!({"secret": "test-secret-key-at-least-32-chars-long!!"}),
        ),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        assert_eq!(
            plugin.supported_protocols(),
            HTTP_FAMILY_PROTOCOLS,
            "Plugin {} should support HTTP_FAMILY_PROTOCOLS",
            name
        );
        assert!(
            !plugin.supported_protocols().contains(&ProxyProtocol::Tcp),
            "Plugin {} must NOT support TCP",
            name
        );
        assert!(
            !plugin.supported_protocols().contains(&ProxyProtocol::Udp),
            "Plugin {} must NOT support UDP",
            name
        );
    }
}

#[test]
fn test_http_family_and_stream_plugins_complete_coverage() {
    let plugins = vec![("mtls_auth", json!({}))];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        assert_eq!(
            plugin.supported_protocols(),
            HTTP_FAMILY_AND_STREAM_PROTOCOLS,
            "Plugin {} should support HTTP_FAMILY_AND_STREAM_PROTOCOLS",
            name
        );
        assert!(
            plugin.supported_protocols().contains(&ProxyProtocol::Tcp),
            "Plugin {} must support TCP",
            name
        );
        assert!(
            plugin.supported_protocols().contains(&ProxyProtocol::Udp),
            "Plugin {} must support UDP/DTLS",
            name
        );
    }
}

#[test]
fn test_http_grpc_plugins_complete_coverage() {
    // AI plugins missing from the base test. ai_request_guard now rejects
    // configs with no policies, so we configure max_messages to satisfy
    // its no-op rejection check.
    let plugins = vec![
        ("ai_token_metrics", json!({})),
        ("ai_request_guard", json!({"max_messages": 100})),
        ("ai_rate_limiter", json!({"token_limit": 1000})),
        (
            "ai_prompt_shield",
            json!({"endpoint": "http://example.com/shield"}),
        ),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        assert_eq!(
            plugin.supported_protocols(),
            HTTP_GRPC_PROTOCOLS,
            "Plugin {} should support HTTP_GRPC_PROTOCOLS",
            name
        );
        assert!(
            !plugin
                .supported_protocols()
                .contains(&ProxyProtocol::WebSocket),
            "Plugin {} must NOT support WebSocket",
            name
        );
        assert!(
            !plugin.supported_protocols().contains(&ProxyProtocol::Tcp),
            "Plugin {} must NOT support TCP",
            name
        );
    }
}

#[test]
fn test_http_only_plugins_complete_coverage() {
    // response_caching and graphql missing from the base test
    let plugins = vec![
        ("response_caching", json!({"ttl_seconds": 60})),
        ("graphql", json!({"max_depth": 100})),
    ];

    for (name, config) in plugins {
        let plugin = make_plugin(name, config);
        assert!(plugin.is_some(), "Failed to create plugin: {}", name);
        let plugin = plugin.unwrap();
        assert_eq!(
            plugin.supported_protocols(),
            HTTP_ONLY_PROTOCOLS,
            "Plugin {} should support HTTP_ONLY_PROTOCOLS",
            name
        );
        assert!(
            !plugin.supported_protocols().contains(&ProxyProtocol::Grpc),
            "Plugin {} must NOT support gRPC",
            name
        );
    }
}
