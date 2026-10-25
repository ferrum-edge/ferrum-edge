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
        labels: Default::default(),
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

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let token = "'\"`UNREGISTERED_TRAFFIC_TOKEN\\tail";
    for (config, field, reason) in [
        (
            json!({"max_connections_per_key": 1, token: true}),
            "tcp_connection_throttle",
            "unknown config field",
        ),
        (
            json!({"max_connections_per_key": true}),
            "`max_connections_per_key`",
            "must be a positive integer",
        ),
    ] {
        let error =
            ferrum_edge::plugins::validate_plugin_config("tcp_connection_throttle", &config)
                .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

#[test]
fn ipv6_prefix_length_is_validated_to_the_documented_range() {
    for accepted in [32, 48, 64, 96, 128] {
        assert!(
            make_plugin(&json!({
                "max_connections_per_key": 1,
                "ipv6_prefix_length": accepted
            }))
            .is_ok(),
            "ipv6_prefix_length {accepted} must be admitted"
        );
    }
    for rejected in [
        json!(0),
        json!(31),
        json!(129),
        json!(256),
        json!(-1),
        json!(64.5),
        json!("64"),
        json!(null),
    ] {
        let error = match make_plugin(&json!({
            "max_connections_per_key": 1,
            "ipv6_prefix_length": rejected.clone()
        })) {
            Ok(_) => panic!("ipv6_prefix_length {rejected} must be rejected"),
            Err(error) => error,
        };
        assert!(error.contains("ipv6_prefix_length"), "{error}");
    }
}

/// Two independently addressed hosts in one `/64` share a budget under the
/// default grouping and keep separate budgets at `/128`.
#[tokio::test]
async fn same_slash_64_ipv6_hosts_share_by_default_and_split_at_128() {
    for config in [
        json!({"max_connections_per_key": 1}),
        json!({"max_connections_per_key": 1, "ipv6_prefix_length": 64}),
    ] {
        let plugin = make_plugin(&config).unwrap();
        let mut first = make_ctx("tcp-proxy", "2001:db8:abcd:12::1", None);
        assert!(matches!(
            plugin.on_stream_connect(&mut first).await,
            PluginResult::Continue
        ));
        let mut neighbour = make_ctx("tcp-proxy", "2001:db8:abcd:12::2", None);
        assert!(
            matches!(
                plugin.on_stream_connect(&mut neighbour).await,
                PluginResult::Reject {
                    status_code: 429,
                    ..
                }
            ),
            "{config}: hosts in one /64 share one budget"
        );
        let mut other_subnet = make_ctx("tcp-proxy", "2001:db8:abcd:13::1", None);
        assert!(matches!(
            plugin.on_stream_connect(&mut other_subnet).await,
            PluginResult::Continue
        ));
        assert_eq!(plugin.tracked_keys_count(), Some(2));
    }

    let per_host = make_plugin(&json!({
        "max_connections_per_key": 1,
        "ipv6_prefix_length": 128
    }))
    .unwrap();
    let mut first = make_ctx("tcp-proxy", "2001:db8:abcd:12::1", None);
    let mut neighbour = make_ctx("tcp-proxy", "2001:db8:abcd:12::2", None);
    assert!(matches!(
        per_host.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    assert!(
        matches!(
            per_host.on_stream_connect(&mut neighbour).await,
            PluginResult::Continue
        ),
        "/128 gives each IPv6 host its own budget"
    );
    let mut same_host = make_ctx("tcp-proxy", "2001:db8:abcd:12::1", None);
    assert!(matches!(
        per_host.on_stream_connect(&mut same_host).await,
        PluginResult::Reject { .. }
    ));
    assert_eq!(per_host.tracked_keys_count(), Some(2));
}

/// NAT64 sources are native IPv6: the default `/64` folds a translated IPv4
/// population into one budget, `/128` keeps each translated client separate.
#[tokio::test]
async fn nat64_clients_follow_the_configured_ipv6_grouping() {
    let grouped = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let mut first = make_ctx("tcp-proxy", "64:ff9b::c000:201", None);
    let mut second = make_ctx("tcp-proxy", "64:ff9b::c000:202", None);
    assert!(matches!(
        grouped.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        grouped.on_stream_connect(&mut second).await,
        PluginResult::Reject { .. }
    ));

    let per_host = make_plugin(&json!({
        "max_connections_per_key": 1,
        "ipv6_prefix_length": 128
    }))
    .unwrap();
    let mut first = make_ctx("tcp-proxy", "64:ff9b::c000:201", None);
    let mut second = make_ctx("tcp-proxy", "64:ff9b::c000:202", None);
    assert!(matches!(
        per_host.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        per_host.on_stream_connect(&mut second).await,
        PluginResult::Continue
    ));
}

/// IPv4 stays per address and IPv4-mapped IPv6 still folds onto it, whatever
/// the IPv6 grouping: the prefix applies to native IPv6 only.
#[tokio::test]
async fn ipv6_prefix_length_never_groups_ipv4_or_mapped_ipv4() {
    for prefix in [32, 64, 128] {
        let plugin = make_plugin(&json!({
            "max_connections_per_key": 1,
            "ipv6_prefix_length": prefix
        }))
        .unwrap();
        let mut native = make_ctx("tcp-proxy", "192.0.2.10", None);
        assert!(matches!(
            plugin.on_stream_connect(&mut native).await,
            PluginResult::Continue
        ));
        let mut mapped = make_ctx("tcp-proxy", "::ffff:192.0.2.10", None);
        assert!(
            matches!(
                plugin.on_stream_connect(&mut mapped).await,
                PluginResult::Reject { .. }
            ),
            "/{prefix}: the mapped form is the same IPv4 principal"
        );
        let mut neighbour = make_ctx("tcp-proxy", "192.0.2.11", None);
        assert!(
            matches!(
                plugin.on_stream_connect(&mut neighbour).await,
                PluginResult::Continue
            ),
            "/{prefix}: IPv4 neighbours are never grouped"
        );
        assert_eq!(plugin.tracked_keys_count(), Some(2));
    }
}

/// Each admitted slot releases the exact key it was admitted under, so under
/// `/128` releasing one host frees only that host and under `/64` a slot
/// released by one host is reusable by its neighbour.
#[tokio::test]
async fn ipv6_grouped_keys_release_exactly_the_admitted_slot() {
    let per_host = make_plugin(&json!({
        "max_connections_per_key": 1,
        "ipv6_prefix_length": 128,
        "cleanup_interval_seconds": 0
    }))
    .unwrap();
    let mut first = make_ctx("tcp-proxy", "2001:db8::1", None);
    let mut second = make_ctx("tcp-proxy", "2001:db8::2", None);
    assert!(matches!(
        per_host.on_stream_connect(&mut first).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        per_host.on_stream_connect(&mut second).await,
        PluginResult::Continue
    ));
    first.release_admission_permits();
    assert_eq!(per_host.tracked_keys_count(), Some(1));
    let mut second_again = make_ctx("tcp-proxy", "2001:db8::2", None);
    assert!(
        matches!(
            per_host.on_stream_connect(&mut second_again).await,
            PluginResult::Reject { .. }
        ),
        "releasing one host must not free another host's slot"
    );
    let mut first_again = make_ctx("tcp-proxy", "2001:db8::1", None);
    assert!(matches!(
        per_host.on_stream_connect(&mut first_again).await,
        PluginResult::Continue
    ));
    first_again.release_admission_permits();
    second.release_admission_permits();
    assert_eq!(per_host.tracked_keys_count(), Some(0));

    let grouped = make_plugin(&json!({
        "max_connections_per_key": 1,
        "cleanup_interval_seconds": 0
    }))
    .unwrap();
    let mut holder = make_ctx("tcp-proxy", "2001:db8::1", None);
    assert!(matches!(
        grouped.on_stream_connect(&mut holder).await,
        PluginResult::Continue
    ));
    holder.release_admission_permits();
    assert_eq!(grouped.tracked_keys_count(), Some(0));
    let mut neighbour = make_ctx("tcp-proxy", "2001:db8::2", None);
    assert!(matches!(
        grouped.on_stream_connect(&mut neighbour).await,
        PluginResult::Continue
    ));
    neighbour.release_admission_permits();
    assert_eq!(grouped.tracked_keys_count(), Some(0));
}

/// Every refusal, and only a refusal, increments the per-proxy Prometheus
/// counter.
#[tokio::test]
async fn refusals_increment_the_per_proxy_rejection_counter() {
    // The registry is process-global; proxy ids unique to this test keep the
    // assertions independent of every other test in the binary.
    const PROXY: &str = "throttle-rejection-counter-proxy";
    const OTHER_PROXY: &str = "throttle-rejection-counter-other-proxy";
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let plugin = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    assert_eq!(
        registry.tcp_connection_throttle_rejections_for_proxy(PROXY),
        0
    );

    let mut admitted = make_ctx(PROXY, "10.20.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut admitted).await,
        PluginResult::Continue
    ));
    let mut other_admitted = make_ctx(OTHER_PROXY, "10.20.0.1", None);
    assert!(matches!(
        plugin.on_stream_connect(&mut other_admitted).await,
        PluginResult::Continue
    ));
    assert_eq!(
        registry.tcp_connection_throttle_rejections_for_proxy(PROXY),
        0,
        "an admission must not count as a refusal"
    );

    for expected in 1..=2 {
        let mut refused = make_ctx(PROXY, "10.20.0.1", None);
        assert!(matches!(
            plugin.on_stream_connect(&mut refused).await,
            PluginResult::Reject { .. }
        ));
        assert_eq!(
            registry.tcp_connection_throttle_rejections_for_proxy(PROXY),
            expected
        );
    }
    assert_eq!(
        registry.tcp_connection_throttle_rejections_for_proxy(OTHER_PROXY),
        0,
        "refusals are attributed to the refusing proxy only"
    );

    let exposition = registry.render_uncached();
    assert!(
        exposition.contains(&format!(
            "ferrum_tcp_connection_throttle_rejections_total{{proxy_id=\"{PROXY}\""
        )),
        "the refusal counter must be exported per proxy"
    );
    admitted.release_admission_permits();
    other_admitted.release_admission_permits();
}

struct DenyAllStreamPolicy;

#[async_trait::async_trait]
impl Plugin for DenyAllStreamPolicy {
    fn name(&self) -> &str {
        "test_deny_all_stream_policy"
    }

    async fn on_stream_connect(&self, _ctx: &mut StreamConnectionContext) -> PluginResult {
        PluginResult::Reject {
            status_code: 403,
            body: r#"{"error":"denied"}"#.into(),
            headers: HashMap::new(),
        }
    }
}

async fn connected_tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let (accepted, _) = listener.accept().await.expect("accept");
    (accepted, client)
}

/// The production TCP `on_stream_connect` runner names the refusing plugin in
/// the setup error that becomes the disconnect summary's `connection_error`,
/// so a throttle refusal is distinguishable from another policy's refusal.
#[tokio::test]
async fn stream_runner_names_the_refusing_plugin() {
    use ferrum_edge::_test_support::tcp_stream_connect_chain_under_trust_fence_for_test;
    use ferrum_edge::proxy::stream_error::{StreamSetupKind, find_stream_setup_error};
    use std::sync::atomic::AtomicBool;

    const PROXY: &str = "throttle-runner-attribution-proxy";
    let (accepted, _client) = connected_tcp_pair().await;
    let throttle = make_plugin(&json!({"max_connections_per_key": 1})).unwrap();
    let chain = vec![Arc::clone(&throttle)];

    let mut holder = make_ctx(PROXY, "10.30.0.1", None);
    let latch = AtomicBool::new(false);
    tcp_stream_connect_chain_under_trust_fence_for_test(
        &chain,
        &mut holder,
        &accepted,
        None,
        &latch,
    )
    .await
    .expect("the first connection is admitted");

    let mut refused = make_ctx(PROXY, "10.30.0.1", None);
    let error = tcp_stream_connect_chain_under_trust_fence_for_test(
        &chain,
        &mut refused,
        &accepted,
        None,
        &latch,
    )
    .await
    .expect_err("the second connection exceeds the limit");
    assert_eq!(
        find_stream_setup_error(&error)
            .expect("typed stream-setup refusal")
            .kind,
        StreamSetupKind::RejectedByPlugin
    );
    assert_eq!(
        error.to_string(),
        "rejected by plugin tcp_connection_throttle (TCP/TLS)"
    );
    assert!(refused.admission_permits.is_empty());

    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let throttle_refusals = registry.tcp_connection_throttle_rejections_for_proxy(PROXY);
    assert_eq!(throttle_refusals, 1);

    // A different stream policy's refusal names that policy and is not
    // counted as a throttle refusal.
    let policy: Arc<dyn Plugin> = Arc::new(DenyAllStreamPolicy);
    let mut denied = make_ctx(PROXY, "10.30.0.2", None);
    let error = tcp_stream_connect_chain_under_trust_fence_for_test(
        &[policy],
        &mut denied,
        &accepted,
        None,
        &latch,
    )
    .await
    .expect_err("the deny-all policy refuses");
    assert_eq!(
        error.to_string(),
        "rejected by plugin test_deny_all_stream_policy (TCP/TLS)"
    );
    assert_eq!(
        registry.tcp_connection_throttle_rejections_for_proxy(PROXY),
        throttle_refusals
    );

    holder.release_admission_permits();
    assert_eq!(throttle.tracked_keys_count(), Some(0));
}
