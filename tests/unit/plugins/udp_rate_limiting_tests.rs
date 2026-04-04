use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, UDP_ONLY_PROTOCOLS, UdpDatagramContext, UdpDatagramDirection,
    UdpDatagramVerdict,
};
use serde_json::json;

fn make_plugin(
    config: serde_json::Value,
) -> ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting {
    ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new(&config).unwrap()
}

fn make_ctx(client_ip: &str, datagram_size: usize) -> UdpDatagramContext {
    UdpDatagramContext {
        client_ip: client_ip.to_string(),
        proxy_id: "proxy-1".to_string(),
        proxy_name: Some("test-proxy".to_string()),
        listen_port: 5353,
        datagram_size,
        direction: UdpDatagramDirection::ClientToBackend,
    }
}

// ── Metadata & Configuration ──────────────────────────────────────────

#[test]
fn name() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));
    assert_eq!(plugin.name(), "udp_rate_limiting");
}

#[test]
fn priority() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));
    assert_eq!(
        plugin.priority(),
        ferrum_edge::plugins::priority::UDP_RATE_LIMITING
    );
}

#[test]
fn supported_protocols() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));
    assert_eq!(plugin.supported_protocols(), UDP_ONLY_PROTOCOLS);
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Udp]);
}

#[test]
fn requires_udp_datagram_hooks() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));
    assert!(plugin.requires_udp_datagram_hooks());
}

#[test]
fn tracked_keys_count_starts_at_zero() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));
    assert_eq!(plugin.tracked_keys_count(), Some(0));
}

// ── Config Validation ─────────────────────────────────────────────────

#[test]
fn config_requires_at_least_one_limit() {
    let result = ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new(&json!({}));
    match result {
        Err(msg) => assert!(msg.contains("at least one of"), "unexpected error: {msg}"),
        Ok(_) => panic!("expected error but got Ok"),
    }
}

#[test]
fn config_accepts_datagrams_only() {
    make_plugin(json!({"datagrams_per_second": 500}));
}

#[test]
fn config_accepts_bytes_only() {
    make_plugin(json!({"bytes_per_second": 1048576}));
}

#[test]
fn config_accepts_both_limits() {
    make_plugin(json!({"datagrams_per_second": 500, "bytes_per_second": 1048576}));
}

#[test]
fn config_window_seconds_defaults_to_one() {
    // Just verify it constructs successfully without window_seconds
    make_plugin(json!({"datagrams_per_second": 100}));
}

#[test]
fn config_custom_window_seconds() {
    make_plugin(json!({"datagrams_per_second": 100, "window_seconds": 5}));
}

// ── Datagram Rate Limiting ────────────────────────────────────────────

#[tokio::test]
async fn datagrams_within_limit_pass() {
    let plugin = make_plugin(json!({"datagrams_per_second": 10}));
    for _ in 0..10 {
        let ctx = make_ctx("10.0.0.1", 100);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
}

#[tokio::test]
async fn datagrams_exceeding_limit_are_dropped() {
    let plugin = make_plugin(json!({"datagrams_per_second": 5}));
    for _ in 0..5 {
        let ctx = make_ctx("10.0.0.1", 100);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // 6th datagram should be dropped
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

#[tokio::test]
async fn bytes_within_limit_pass() {
    let plugin = make_plugin(json!({"bytes_per_second": 1000}));
    // 5 datagrams of 200 bytes each = 1000 total, should all pass
    for _ in 0..5 {
        let ctx = make_ctx("10.0.0.1", 200);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
}

#[tokio::test]
async fn bytes_exceeding_limit_are_dropped() {
    let plugin = make_plugin(json!({"bytes_per_second": 500}));
    // 5 datagrams of 100 bytes = 500, all pass
    for _ in 0..5 {
        let ctx = make_ctx("10.0.0.1", 100);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // 6th datagram pushes over 500 bytes
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

// ── Per-Client Isolation ──────────────────────────────────────────────

#[tokio::test]
async fn different_clients_have_independent_limits() {
    let plugin = make_plugin(json!({"datagrams_per_second": 3}));

    // Client A uses 3 datagrams (limit)
    for _ in 0..3 {
        let ctx = make_ctx("10.0.0.1", 100);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // Client A: 4th is dropped
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);

    // Client B still has full budget
    for _ in 0..3 {
        let ctx = make_ctx("10.0.0.2", 100);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // Client B: 4th is dropped
    let ctx = make_ctx("10.0.0.2", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

#[tokio::test]
async fn tracked_keys_count_reflects_active_clients() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));

    let ctx1 = make_ctx("10.0.0.1", 100);
    plugin.on_udp_datagram(&ctx1).await;
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    let ctx2 = make_ctx("10.0.0.2", 100);
    plugin.on_udp_datagram(&ctx2).await;
    assert_eq!(plugin.tracked_keys_count(), Some(2));

    // Same client doesn't increase count
    let ctx1_again = make_ctx("10.0.0.1", 100);
    plugin.on_udp_datagram(&ctx1_again).await;
    assert_eq!(plugin.tracked_keys_count(), Some(2));
}

// ── Combined Limits ───────────────────────────────────────────────────

#[tokio::test]
async fn both_limits_enforced_independently() {
    // 10 datagrams/sec AND 500 bytes/sec
    let plugin = make_plugin(json!({
        "datagrams_per_second": 10,
        "bytes_per_second": 500
    }));

    // Send 5 datagrams of 100 bytes each (500 bytes total = at byte limit)
    for _ in 0..5 {
        let ctx = make_ctx("10.0.0.1", 100);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // 6th datagram: datagram count (6) is within limit (10), but bytes (600) exceed 500
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

#[tokio::test]
async fn datagram_limit_triggers_before_byte_limit() {
    // 3 datagrams/sec AND 10000 bytes/sec
    let plugin = make_plugin(json!({
        "datagrams_per_second": 3,
        "bytes_per_second": 10000
    }));

    for _ in 0..3 {
        let ctx = make_ctx("10.0.0.1", 10);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // 4th: datagram limit (3) exceeded, even though bytes (40) is well within 10000
    let ctx = make_ctx("10.0.0.1", 10);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

// ── Window Boundary ───────────────────────────────────────────────────

#[tokio::test]
async fn window_resets_after_duration() {
    // Use a very short window to test reset (1 second)
    let plugin = make_plugin(json!({"datagrams_per_second": 2, "window_seconds": 1}));

    // Use up the limit
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);

    // Wait for window to roll over
    tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;

    // Should be allowed again
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
}

// ── Edge Cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn zero_size_datagram() {
    let plugin = make_plugin(json!({"bytes_per_second": 100}));
    let ctx = make_ctx("10.0.0.1", 0);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
}

#[tokio::test]
async fn large_datagram_exceeds_byte_limit_immediately() {
    let plugin = make_plugin(json!({"bytes_per_second": 100}));
    // Single 65535-byte datagram exceeds 100 byte/s limit
    let ctx = make_ctx("10.0.0.1", 65535);
    // First datagram still passes (counter starts at 0, increment happens, then check)
    // After increment: bytes = 65535 > 100, so this is dropped
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

#[tokio::test]
async fn first_datagram_always_passes_within_count_limit() {
    let plugin = make_plugin(json!({"datagrams_per_second": 1}));
    let ctx = make_ctx("10.0.0.1", 50);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
    // Second is dropped
    let ctx = make_ctx("10.0.0.1", 50);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

// ── Default Trait Methods ─────────────────────────────────────────────

#[tokio::test]
async fn default_trait_does_not_require_datagram_hooks() {
    // Verify that a non-UDP plugin returns false for requires_udp_datagram_hooks
    use ferrum_edge::plugins::create_plugin;
    let plugin = create_plugin("stdout_logging", &json!({}))
        .unwrap()
        .unwrap();
    assert!(!plugin.requires_udp_datagram_hooks());
}

#[tokio::test]
async fn default_trait_on_udp_datagram_returns_forward() {
    use ferrum_edge::plugins::create_plugin;
    let plugin = create_plugin("stdout_logging", &json!({}))
        .unwrap()
        .unwrap();
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
}
