use ferrum_edge::config::types::{BackendScheme, Consumer};
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, StreamConnectionContext, create_plugin,
};
use ferrum_edge::proxy::proxy_protocol::{ProxyProtocolResult, apply_proxy_result};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

fn make_plugin(config: &Value) -> Result<Arc<dyn Plugin>, String> {
    create_plugin("tcp_connection_throttle", config)?
        .ok_or_else(|| "tcp_connection_throttle is not registered".to_string())
}

fn make_consumer(username: &str) -> Consumer {
    Consumer {
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

fn make_ctx(proxy_id: &str, ip: &str, consumer: Option<&str>) -> StreamConnectionContext {
    make_ctx_in_namespace(
        proxy_id,
        &ferrum_edge::config::types::default_namespace(),
        ip,
        consumer,
    )
}

fn make_ctx_in_namespace(
    proxy_id: &str,
    proxy_namespace: &str,
    ip: &str,
    consumer: Option<&str>,
) -> StreamConnectionContext {
    let mut ctx = StreamConnectionContext::new(
        ip.to_string(),
        ip.to_string(),
        proxy_id.to_string(),
        Some(format!("TCP Proxy {proxy_id}")),
        5432,
        BackendScheme::Tcp,
        Arc::new(ferrum_edge::ConsumerIndex::new(&[])),
    );
    ctx.proxy_namespace = proxy_namespace.to_string();
    ctx.identified_consumer = consumer.map(|c| Arc::new(make_consumer(c)));
    ctx
}

#[test]
fn test_tcp_connection_throttle_requires_positive_limit() {
    assert!(make_plugin(&json!(null)).is_err());
    assert!(make_plugin(&json!([])).is_err());
    assert!(make_plugin(&json!({})).is_err());
    assert!(make_plugin(&json!({"max_connections_per_key": "1"})).is_err());
    assert!(make_plugin(&json!({"max_connections_per_key": 0})).is_err());
    assert!(
        make_plugin(&json!({
            "max_connections_per_key": 1,
            "cleanup_interval_seconds": "60"
        }))
        .is_err()
    );
    assert!(
        make_plugin(&json!({
            "max_connections_per_key": 1,
            "cleanup_interval_seconds": 0
        }))
        .is_ok()
    );
    assert!(
        make_plugin(&json!({
            "max_connections_per_key": 1,
            "cleanup_intervl_seconds": 60
        }))
        .is_err()
    );
    assert!(
        make_plugin(&json!({
            "max_connections_per_key": 1,
            "cleanup_interval_seconds": 86401
        }))
        .is_err()
    );
}

#[test]
fn test_tcp_connection_throttle_protocol_and_priority() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 2})).unwrap();
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
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

/// A global-scope throttle shares one plugin instance across every namespace.
/// Keys must include `proxy_namespace` so the same bare `proxy_id` in two
/// tenants keeps independent budgets (Refs GHSA-rp87-rhqp-g9h8).
#[tokio::test]
async fn test_tcp_connection_throttle_isolates_budget_by_proxy_namespace() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    let mut tenant_a = make_ctx_in_namespace("shared-proxy", "tenant-a", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut tenant_a).await,
        PluginResult::Continue
    ));

    let mut tenant_b = make_ctx_in_namespace("shared-proxy", "tenant-b", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut tenant_b).await,
        PluginResult::Continue
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    let mut tenant_a_second = make_ctx_in_namespace("shared-proxy", "tenant-a", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut tenant_a_second).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));

    let mut tenant_b_second = make_ctx_in_namespace("shared-proxy", "tenant-b", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut tenant_b_second).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));
}

#[tokio::test]
async fn test_tcp_connection_throttle_rejects_second_connection_for_same_ip() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    let mut ctx1 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    let mut ctx2 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn test_tcp_connection_throttle_uses_canonical_ingress_identity() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    let mut native = make_ctx("tcp-proxy", "192.0.2.10", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut native).await,
        PluginResult::Continue
    ));

    let mapped_peer = "[::ffff:192.0.2.10]:4321".parse().unwrap();
    let (mapped_ip, _) = apply_proxy_result(ProxyProtocolResult::NoAddress, &mapped_peer);
    let mut mapped = make_ctx("tcp-proxy", &mapped_ip, None);
    assert!(matches!(
        plugin.on_stream_connect(&mut mapped).await,
        PluginResult::Reject {
            status_code: 429,
            ..
        }
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

#[tokio::test]
async fn test_tcp_connection_throttle_releases_slot_on_disconnect() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    let mut ctx1 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx1).await,
        PluginResult::Continue
    ));

    assert!(ctx1.metadata.is_none());
    ctx1.release_admission_permits();
    assert_eq!(plugin.tracked_keys_count(), Some(0));

    let mut ctx2 = make_ctx("tcp-proxy", "10.0.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut ctx2).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_tcp_connection_throttle_canonicalizes_ipv4_mapped_identity() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let mut ipv4 = make_ctx("tcp-proxy", "192.0.2.10", None);
    let mut mapped = make_ctx("tcp-proxy", "::ffff:192.0.2.10", None);

    assert!(matches!(
        plugin.on_stream_connect(&mut ipv4).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        plugin.on_stream_connect(&mut mapped).await,
        PluginResult::Reject { .. }
    ));
}

#[tokio::test]
async fn test_tcp_connection_throttle_multiple_instances_use_independent_permits() {
    let first = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let second = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let mut connection = make_ctx("tcp-proxy", "10.0.0.1", None);

    assert!(matches!(
        first.on_stream_connect(&mut connection).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        second.on_stream_connect(&mut connection).await,
        PluginResult::Continue
    ));
    assert_eq!(connection.admission_permits.len(), 2);
    assert!(connection.metadata.is_none());

    connection.release_admission_permits();
    connection.release_admission_permits();
    assert_eq!(first.tracked_keys_count(), Some(0));
    assert_eq!(second.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_tcp_connection_throttle_auth_boundary_permits_do_not_overwrite() {
    let before_auth = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let after_auth = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let mut connection = make_ctx("tcp-proxy", "10.0.0.1", None);

    assert!(matches!(
        before_auth.on_stream_connect(&mut connection).await,
        PluginResult::Continue
    ));
    connection.identified_consumer = Some(Arc::new(make_consumer("alice")));
    assert!(matches!(
        after_auth.on_stream_connect(&mut connection).await,
        PluginResult::Continue
    ));

    let mut same_consumer = make_ctx("tcp-proxy", "10.0.0.2", None);
    assert!(matches!(
        before_auth.on_stream_connect(&mut same_consumer).await,
        PluginResult::Continue
    ));
    same_consumer.identified_consumer = Some(Arc::new(make_consumer("alice")));
    assert!(matches!(
        after_auth.on_stream_connect(&mut same_consumer).await,
        PluginResult::Reject { .. }
    ));
    same_consumer.release_admission_permits();
    connection.release_admission_permits();
    assert_eq!(before_auth.tracked_keys_count(), Some(0));
    assert_eq!(after_auth.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_tcp_connection_throttle_release_admission_race_never_detaches_increment() {
    let plugin = make_plugin(&json!({
        "max_connections_per_key": 1,
        "cleanup_interval_seconds": 0
    }))
    .unwrap();

    for _ in 0..256 {
        let mut current = make_ctx("tcp-proxy", "10.0.0.9", None);
        assert!(matches!(
            plugin.on_stream_connect(&mut current).await,
            PluginResult::Continue
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let release_barrier = Arc::clone(&barrier);
        let release = tokio::spawn(async move {
            release_barrier.wait().await;
            current.release_admission_permits();
        });
        let admit_barrier = Arc::clone(&barrier);
        let admit_plugin = Arc::clone(&plugin);
        let admit = tokio::spawn(async move {
            let mut candidate = make_ctx("tcp-proxy", "10.0.0.9", None);
            admit_barrier.wait().await;
            let admitted = matches!(
                admit_plugin.on_stream_connect(&mut candidate).await,
                PluginResult::Continue
            );
            (admitted, candidate)
        });
        barrier.wait().await;
        release.await.unwrap();
        let (admitted, mut candidate) = admit.await.unwrap();
        if !admitted {
            assert!(matches!(
                plugin.on_stream_connect(&mut candidate).await,
                PluginResult::Continue
            ));
        }
        assert_eq!(plugin.tracked_keys_count(), Some(1));

        let mut over_limit = make_ctx("tcp-proxy", "10.0.0.9", None);
        assert!(matches!(
            plugin.on_stream_connect(&mut over_limit).await,
            PluginResult::Reject { .. }
        ));
        candidate.release_admission_permits();
        assert_eq!(plugin.tracked_keys_count(), Some(0));
    }
}

#[tokio::test]
async fn test_tcp_connection_throttle_concurrent_exact_limit() {
    const LIMIT: usize = 8;
    const ATTEMPTS: usize = 32;
    let plugin = make_plugin(&json!({"max_connections_per_key": LIMIT})).unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(ATTEMPTS + 1));
    let mut tasks = Vec::new();
    for _ in 0..ATTEMPTS {
        let plugin = Arc::clone(&plugin);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let mut ctx = make_ctx("tcp-proxy", "10.0.0.10", None);
            barrier.wait().await;
            let admitted = matches!(
                plugin.on_stream_connect(&mut ctx).await,
                PluginResult::Continue
            );
            (admitted, ctx)
        }));
    }
    barrier.wait().await;

    let mut admitted = Vec::new();
    for task in tasks {
        let (was_admitted, ctx) = task.await.unwrap();
        if was_admitted {
            admitted.push(ctx);
        }
    }
    assert_eq!(admitted.len(), LIMIT);
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    for mut ctx in admitted {
        ctx.release_admission_permits();
    }
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

#[tokio::test]
async fn test_tcp_connection_throttle_uses_consumer_identity_when_present() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

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
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

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

/// Admission and release must use the SAME canonical key across
/// representations (advisory GHSA-vjwj-657f-5w9g). A release keyed on the
/// mapped text while admission keyed on the native text would leak the slot
/// permanently; the reverse would let one host hold two budgets.
#[tokio::test]
async fn disconnect_release_returns_the_slot_to_the_canonical_identity() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    // Admit as the mapped form, release, then re-admit as the native form.
    let mut mapped = make_ctx("tcp-proxy", "::ffff:192.0.2.10", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut mapped).await,
        PluginResult::Continue
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
    mapped.release_admission_permits();
    assert_eq!(
        plugin.tracked_keys_count(),
        Some(0),
        "releasing a mapped-form admission must remove the canonical entry"
    );

    let mut native = make_ctx("tcp-proxy", "192.0.2.10", None);
    assert!(
        matches!(
            plugin.on_stream_connect(&mut native).await,
            PluginResult::Continue
        ),
        "the released slot must be available to the same principal's native form"
    );

    // ...and the budget is still one slot for that principal, not two.
    let mut again = make_ctx("tcp-proxy", "::ffff:192.0.2.10", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut again).await,
        PluginResult::Reject { .. }
    ));
    native.release_admission_permits();
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

/// A genuine IPv6 client keeps a separate budget from the IPv4 address its
/// low-order bits encode.
#[tokio::test]
async fn true_ipv6_client_keeps_its_own_connection_budget() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    let mut native = make_ctx("tcp-proxy", "192.0.2.10", None);
    let mut compatible = make_ctx("tcp-proxy", "::192.0.2.10", None);
    let mut distinct = make_ctx("tcp-proxy", "2001:db8::10", None);

    assert!(matches!(
        plugin.on_stream_connect(&mut native).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        plugin.on_stream_connect(&mut compatible).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        plugin.on_stream_connect(&mut distinct).await,
        PluginResult::Continue
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(3));
}

/// PROXY-protocol-forwarded sources are folded at the same boundary, so an L4
/// load balancer that reports the client in `AF_INET6` form does not hand that
/// client a second connection budget.
#[tokio::test]
async fn proxy_protocol_forwarded_source_shares_the_native_budget() {
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();

    let lb_peer = "10.0.0.7:5000".parse().unwrap();
    let mapped_src = "[::ffff:192.0.2.10]:33000".parse().unwrap();
    let native_src = "192.0.2.10:33001".parse().unwrap();

    let (from_mapped, _) = apply_proxy_result(
        ProxyProtocolResult::Forwarded {
            src: mapped_src,
            dst: lb_peer,
        },
        &lb_peer,
    );
    let (from_native, _) = apply_proxy_result(
        ProxyProtocolResult::Forwarded {
            src: native_src,
            dst: lb_peer,
        },
        &lb_peer,
    );
    assert_eq!(from_mapped, from_native);

    let mut first = make_ctx("tcp-proxy", &from_mapped, None);
    assert!(matches!(
        plugin.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    let mut second = make_ctx("tcp-proxy", &from_native, None);
    assert!(matches!(
        plugin.on_stream_connect(&mut second).await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}
