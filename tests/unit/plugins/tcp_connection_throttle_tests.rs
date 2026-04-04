use ferrum_edge::config::types::{BackendProtocol, Consumer};
use ferrum_edge::plugins::tcp_connection_throttle::TcpConnectionThrottle;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamConnectionContext, StreamTransactionSummary,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

fn make_consumer(username: &str) -> Consumer {
    Consumer {
        id: format!("consumer-{username}"),
        username: username.to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn make_ctx(proxy_id: &str, ip: &str, consumer: Option<&str>) -> StreamConnectionContext {
    StreamConnectionContext {
        client_ip: ip.to_string(),
        proxy_id: proxy_id.to_string(),
        proxy_name: Some(format!("TCP Proxy {proxy_id}")),
        listen_port: 5432,
        backend_protocol: BackendProtocol::Tcp,
        consumer_index: Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
        identified_consumer: consumer.map(make_consumer),
        authenticated_identity: None,
        metadata: HashMap::new(),
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
    }
}

fn make_summary(metadata: HashMap<String, String>) -> StreamTransactionSummary {
    StreamTransactionSummary {
        proxy_id: "tcp-proxy".to_string(),
        proxy_name: Some("TCP Proxy".to_string()),
        client_ip: "127.0.0.1".to_string(),
        backend_target: "127.0.0.1:5432".to_string(),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        protocol: "tcp".to_string(),
        listen_port: 5432,
        duration_ms: 1.0,
        bytes_sent: 0,
        bytes_received: 0,
        connection_error: None,
        error_class: None,
        timestamp_connected: "2026-04-02T00:00:00Z".to_string(),
        timestamp_disconnected: "2026-04-02T00:00:01Z".to_string(),
        metadata,
    }
}

#[test]
fn test_tcp_connection_throttle_requires_positive_limit() {
    assert!(TcpConnectionThrottle::new(&json!({})).is_err());
    assert!(TcpConnectionThrottle::new(&json!({"max_connections_per_key": 0})).is_err());
}

#[test]
fn test_tcp_connection_throttle_protocol_and_priority() {
    let plugin = TcpConnectionThrottle::new(&json!({"max_connections_per_key": 2})).unwrap();
    assert_eq!(plugin.name(), "tcp_connection_throttle");
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::TCP_CONNECTION_THROTTLE
    );
    assert_eq!(
        plugin.supported_protocols(),
        ferrum_edge::plugins::TCP_ONLY_PROTOCOLS
    );
    assert!(plugin.supported_protocols().contains(&ProxyProtocol::Tcp));
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Udp));
}

#[tokio::test]
async fn test_tcp_connection_throttle_rejects_second_connection_for_same_ip() {
    let plugin = TcpConnectionThrottle::new(&json!({"max_connections_per_key": 1})).unwrap();

    let mut ctx1 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));

    let mut ctx2 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));
}

#[tokio::test]
async fn test_tcp_connection_throttle_releases_slot_on_disconnect() {
    let plugin = TcpConnectionThrottle::new(&json!({"max_connections_per_key": 1})).unwrap();

    let mut ctx1 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));

    plugin
        .on_stream_disconnect(&make_summary(ctx1.metadata.clone()))
        .await;

    let mut ctx2 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_tcp_connection_throttle_uses_consumer_identity_when_present() {
    let plugin = TcpConnectionThrottle::new(&json!({"max_connections_per_key": 1})).unwrap();

    let mut ctx1 = make_ctx("tcp-proxy", "10.0.0.1", Some("alice"));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));

    let mut ctx2 = make_ctx("tcp-proxy", "10.0.0.2", Some("alice"));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));

    let mut ctx3 = make_ctx("tcp-proxy", "10.0.0.3", Some("bob"));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx3).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_tcp_connection_throttle_allows_same_identity_on_different_proxies() {
    let plugin = TcpConnectionThrottle::new(&json!({"max_connections_per_key": 1})).unwrap();

    let mut ctx1 = make_ctx("tcp-proxy-a", "10.0.0.1", Some("alice"));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));

    let mut ctx2 = make_ctx("tcp-proxy-b", "10.0.0.2", Some("alice"));
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Continue
    ));

    let mut ctx3 = make_ctx("tcp-proxy-c", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx3).await,
        PluginResult::Continue
    ));
}
