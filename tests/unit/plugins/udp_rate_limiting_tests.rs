use std::sync::Arc;
use std::sync::atomic::Ordering;

use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, ProxyProtocol, StreamBytesKind, UDP_ONLY_PROTOCOLS,
    UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
};
use serde_json::json;

fn make_plugin(
    config: serde_json::Value,
) -> ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting {
    ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
        &config,
        PluginHttpClient::default(),
    )
    .unwrap()
}

fn make_ctx(client_ip: &str, datagram_size: usize) -> UdpDatagramContext<'static> {
    let client_ip: std::net::IpAddr = client_ip.parse().expect("test client IP parses");
    let client_addr = std::net::SocketAddr::new(client_ip, 5353);
    UdpDatagramContext {
        client_ip: ferrum_edge::proxy::udp_proxy::udp_session_client_ip(client_addr),
        client_ip_addr: ferrum_edge::proxy::udp_proxy::udp_session_client_addr(client_addr),
        proxy_id: Arc::from("proxy-1"),
        proxy_name: Some(Arc::from("test-proxy")),
        listen_port: 5353,
        datagram_size,
        direction: UdpDatagramDirection::ClientToBackend,
        // udp_rate_limiting keys off datagram_size, not payload bytes.
        payload: &[],
        payload_kind: StreamBytesKind::PlaintextWire,
        metadata_sink: None,
    }
}

// ── Metadata & Configuration ──────────────────────────────────────────

#[test]
fn name() {
    let plugin = make_plugin(json!({"datagrams_per_second": 100}));
    assert_eq!(plugin.name(), "udp_rate_limiting");
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
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

#[test]
fn udp_session_admission_canonicalizes_mapped_client_identity() {
    let mapped: std::net::SocketAddr = "[::ffff:192.0.2.10]:5353".parse().unwrap();
    assert_eq!(
        ferrum_edge::proxy::udp_proxy::udp_session_client_ip(mapped).as_ref(),
        "192.0.2.10"
    );
}

#[test]
fn zero_length_udp_request_retains_bounded_response_budget() {
    use ferrum_edge::udp_amplification::udp_amplification_response_budget;

    assert_eq!(udp_amplification_response_budget(0, 1.0), 1);
    assert_eq!(udp_amplification_response_budget(0, 0.25), 1);
    assert_eq!(udp_amplification_response_budget(1, 1.0), 1);
    assert_eq!(udp_amplification_response_budget(4, 1.0), 4);
}

#[test]
fn warmup_hostnames_for_redis() {
    let plugin = make_plugin(json!({
        "datagrams_per_second": 100,
        "sync_mode": "redis",
        "redis_url": "redis://redis.internal:6379"
    }));

    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["redis.internal".to_string()]
    );
}

// ── Config Validation ─────────────────────────────────────────────────

#[test]
fn config_rejects_non_object() {
    let result = ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
        &json!("bad"),
        PluginHttpClient::default(),
    );
    match result {
        Err(msg) => assert!(
            msg.contains("config must be an object"),
            "unexpected error: {msg}"
        ),
        Ok(_) => panic!("expected error but got Ok"),
    }
}

#[test]
fn config_requires_at_least_one_limit() {
    let result = ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
        &json!({}),
        PluginHttpClient::default(),
    );
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

#[test]
fn config_rejects_zero_limits_and_window() {
    for config in [
        json!({"datagrams_per_second": 0}),
        json!({"bytes_per_second": 0}),
        json!({"datagrams_per_second": 100, "window_seconds": 0}),
    ] {
        let result = ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
            &config,
            PluginHttpClient::default(),
        );
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn config_rejects_invalid_numeric_types() {
    for config in [
        json!({"datagrams_per_second": "100"}),
        json!({"bytes_per_second": "1000"}),
        json!({"datagrams_per_second": 100, "window_seconds": "5"}),
        json!({"datagrams_per_second": 100, "sync_mode": "database"}),
    ] {
        let result = ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
            &config,
            PluginHttpClient::default(),
        );
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn config_rejects_per_window_overflow() {
    let result = ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
        &json!({"datagrams_per_second": u64::MAX, "window_seconds": 2}),
        PluginHttpClient::default(),
    );
    match result {
        Err(msg) => assert!(msg.contains("overflows u64"), "unexpected error: {msg}"),
        Ok(_) => panic!("expected overflow error but got Ok"),
    }
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
    // 6th datagram should be dropped and exported by the aggregate limiter
    // metric.
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry.rate_limit_exceeded.load(Ordering::Relaxed);
    let ctx = make_ctx("10.0.0.1", 100);
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
    assert!(registry.rate_limit_exceeded.load(Ordering::Relaxed) > before);
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

#[tokio::test]
async fn mapped_ipv4_shares_native_client_budget() {
    let plugin = make_plugin(json!({"datagrams_per_second": 1}));

    let native = make_ctx("192.0.2.10", 100);
    assert_eq!(
        plugin.on_udp_datagram(&native).await,
        UdpDatagramVerdict::Forward
    );

    let mapped = make_ctx("::ffff:192.0.2.10", 100);
    assert_eq!(
        plugin.on_udp_datagram(&mapped).await,
        UdpDatagramVerdict::Drop
    );
    assert_eq!(plugin.tracked_keys_count(), Some(1));
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

// ── Direction handling ───────────────────────────────────────────────

#[tokio::test]
async fn both_directions_share_same_per_client_window() {
    // ctx.direction is intentionally NOT used by udp_rate_limiting — the per-IP
    // window aggregates client→backend and backend→client traffic. Verify by
    // alternating directions and confirming the limit still trips.
    let plugin = make_plugin(json!({"datagrams_per_second": 4}));
    for _ in 0..2 {
        let mut ctx = make_ctx("10.0.0.1", 100);
        ctx.direction = UdpDatagramDirection::ClientToBackend;
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    for _ in 0..2 {
        let mut ctx = make_ctx("10.0.0.1", 100);
        ctx.direction = UdpDatagramDirection::BackendToClient;
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    // 5th datagram (in either direction) crosses the 4/sec cap
    let mut ctx = make_ctx("10.0.0.1", 100);
    ctx.direction = UdpDatagramDirection::BackendToClient;
    assert_eq!(plugin.on_udp_datagram(&ctx).await, UdpDatagramVerdict::Drop);
}

// ── Capacity bookkeeping (#2314) ──────────────────────────────────────

#[tokio::test]
async fn steady_datagram_path_does_not_call_all_shard_len() {
    use ferrum_edge::_test_support::RateLimitCleanupHarness;

    let h = RateLimitCleanupHarness::new();
    let epoch = h.udp_epoch_base();
    for idx in 0..8 {
        h.seed_udp(&format!("10.0.0.{idx}"), epoch);
    }
    let before = h.udp_all_shard_len_calls();

    // Steady under-cap observations: maybe_evict loads the atomic count twice
    // in the historical shape, but must never take every shard read lock.
    for _ in 0..1_000 {
        let _ = h.maybe_evict_udp_at(epoch);
    }
    assert_eq!(
        h.udp_all_shard_len_calls(),
        before,
        "steady maybe_evict must not call DashMap::len()"
    );
    assert_eq!(h.udp_tracked(), Some(h.udp_map_len()));
}

#[tokio::test]
async fn on_udp_datagram_steady_admission_skips_all_shard_len() {
    use ferrum_edge::_test_support::{
        udp_rate_limiting_all_shard_len_calls_for_test, udp_rate_limiting_map_len_for_test,
        udp_rate_limiting_with_shards_for_test,
    };

    let plugin_4 =
        udp_rate_limiting_with_shards_for_test(&json!({"datagrams_per_second": 1_000_000}), 4);
    let plugin_256 =
        udp_rate_limiting_with_shards_for_test(&json!({"datagrams_per_second": 1_000_000}), 256);

    for plugin in [&plugin_4, &plugin_256] {
        for idx in 0..8u8 {
            let ctx = make_ctx(&format!("10.0.0.{idx}"), 64);
            assert_eq!(
                plugin.on_udp_datagram(&ctx).await,
                UdpDatagramVerdict::Forward
            );
        }
    }

    let before_4 = udp_rate_limiting_all_shard_len_calls_for_test(&plugin_4);
    let before_256 = udp_rate_limiting_all_shard_len_calls_for_test(&plugin_256);
    for _ in 0..500 {
        let ctx = make_ctx("10.0.0.1", 64);
        assert_eq!(
            plugin_4.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
        assert_eq!(
            plugin_256.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    let calls_4 = udp_rate_limiting_all_shard_len_calls_for_test(&plugin_4) - before_4;
    let calls_256 = udp_rate_limiting_all_shard_len_calls_for_test(&plugin_256) - before_256;
    assert_eq!(
        calls_4, 0,
        "steady admission must not call DashMap::len() (4 shards)"
    );
    assert_eq!(
        calls_256, 0,
        "steady admission must not call DashMap::len() (256 shards)"
    );
    assert_eq!(
        calls_4, calls_256,
        "steady all-shard work must not scale with DashMap shard count"
    );
    assert_eq!(
        plugin_4.tracked_keys_count(),
        Some(udp_rate_limiting_map_len_for_test(&plugin_4))
    );
}

#[tokio::test]
async fn redis_mode_datagram_path_skips_local_all_shard_scans() {
    use ferrum_edge::_test_support::{
        udp_rate_limiting_all_shard_len_calls_for_test, udp_rate_limiting_epoch_base_for_test,
        udp_rate_limiting_maybe_evict_at_for_test, udp_rate_limiting_seed_client_at_for_test,
    };

    let plugin = make_plugin(json!({
        "datagrams_per_second": 1_000_000,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:9/0",
        "redis_health_check_interval_seconds": 1
    }));
    let epoch = udp_rate_limiting_epoch_base_for_test(&plugin);
    udp_rate_limiting_seed_client_at_for_test(&plugin, "10.0.0.1", 1, epoch);
    udp_rate_limiting_seed_client_at_for_test(&plugin, "10.0.0.2", 1, epoch);
    let before = udp_rate_limiting_all_shard_len_calls_for_test(&plugin);
    for _ in 0..2_000 {
        let _ = udp_rate_limiting_maybe_evict_at_for_test(&plugin, epoch);
    }
    assert_eq!(
        udp_rate_limiting_all_shard_len_calls_for_test(&plugin),
        before,
        "Redis-mode local fallback must not all-shard scan per datagram"
    );
}

#[test]
fn concurrent_insert_prune_and_cap_keep_exact_entry_count() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use ferrum_edge::_test_support::RateLimitCleanupHarness;

    let h = std::sync::Arc::new(RateLimitCleanupHarness::new());
    let max_seen = std::sync::Arc::new(AtomicUsize::new(0));
    let epoch = h.udp_epoch_base();
    let mut handles = Vec::new();

    for worker in 0..8 {
        let h = std::sync::Arc::clone(&h);
        let max_seen = std::sync::Arc::clone(&max_seen);
        handles.push(thread::spawn(move || {
            for i in 0..512u32 {
                let ip = format!("10.{worker}.{}.{}", (i / 256) % 256, i % 256);
                let _ = h.seed_udp_with_cap(&ip, epoch, 32);
                let count = h.udp_tracked().unwrap_or(usize::MAX);
                max_seen.fetch_max(count, Ordering::Relaxed);
            }
        }));
    }
    {
        let h = std::sync::Arc::clone(&h);
        let max_seen = std::sync::Arc::clone(&max_seen);
        handles.push(thread::spawn(move || {
            for second in 20..84 {
                h.arm_udp_periodic();
                let _ = h.maybe_evict_udp_at(epoch + Duration::from_secs(second));
                let count = h.udp_tracked().unwrap_or(usize::MAX);
                max_seen.fetch_max(count, Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("worker joins");
    }

    assert!(max_seen.load(Ordering::Relaxed) <= 32);
    assert!(h.udp_tracked().unwrap_or(usize::MAX) <= 32);
    assert_eq!(
        h.udp_tracked(),
        Some(h.udp_map_len()),
        "atomic count must match after concurrent capped insertion and expiry removal"
    );

    // Expiry removes every stale key and releases the exact same slots.
    h.arm_udp_periodic();
    let _ = h.maybe_evict_udp_at(epoch + Duration::from_secs(100));
    assert_eq!(h.udp_tracked(), Some(0));
    assert_eq!(h.udp_map_len(), 0);

    // Refill through the cap gate. Uncapped test seeds model legacy/repair
    // pressure above the steady admission cap; cleanup must not delete live
    // budgets, and previously unseen keys remain denied.
    let active = epoch + Duration::from_secs(200);
    for i in 0..96 {
        h.seed_udp(&format!("192.0.2.{i}"), active);
    }
    assert_eq!(h.udp_tracked(), Some(96));
    let _ = h.maybe_evict_udp_at_with_cap(active, 32);
    assert_eq!(h.udp_tracked(), Some(96));
    assert_eq!(h.udp_map_len(), 96);
    assert!(!h.seed_udp_with_cap("198.51.100.1", active, 32));
}

// ── Bounded rejection diagnostics (GHSA-x6v4-3gwg-3rw6) ───────────────

fn reset_udp_rejection_warn_state(
    plugin: &ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting,
) {
    ferrum_edge::_test_support::udp_rate_limiting_reset_rejection_warn_for_test(plugin);
}

fn rejection_warn_global() -> ferrum_edge::util::atomic_log_rate_limiter::AtomicLogRateLimiter {
    ferrum_edge::_test_support::atomic_log_rate_limiter_with_window_for_test(1_000)
}

fn record_rejection_warn(
    plugin: &ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting,
    global: &ferrum_edge::util::atomic_log_rate_limiter::AtomicLogRateLimiter,
    limit_kind: &'static str,
    proxy_id: &str,
    now_ms: u64,
) -> ferrum_edge::_test_support::UdpRejectionWarnDecisionForTest {
    ferrum_edge::_test_support::udp_rate_limiting_record_rejection_warn_detail_for_test(
        plugin, global, limit_kind, proxy_id, now_ms,
    )
}

#[test]
fn rejection_warn_emits_once_per_window_under_identical_timestamp_flood() {
    let plugin = make_plugin(json!({"datagrams_per_second": 1}));
    let global = rejection_warn_global();
    reset_udp_rejection_warn_state(&plugin);

    let mut emissions = 0usize;
    for _ in 0..10_000 {
        if record_rejection_warn(&plugin, &global, "datagram_count", "proxy-1", 1_000).emitted {
            emissions += 1;
        }
    }
    assert_eq!(
        emissions, 1,
        "identical timestamps within one 1s window must emit at most once per instance"
    );
}

#[test]
fn rejection_warn_rolls_window_and_carries_suppressed_count() {
    let plugin = make_plugin(json!({"datagrams_per_second": 1}));
    let global = rejection_warn_global();
    reset_udp_rejection_warn_state(&plugin);

    let first = record_rejection_warn(&plugin, &global, "datagram_count", "proxy-1", 0);
    assert!(first.emitted);
    assert_eq!(first.instance_suppressed, Some(0));
    assert_eq!(first.global_suppressed, Some(0));

    for t in 1..=999 {
        let decision = record_rejection_warn(&plugin, &global, "datagram_count", "proxy-1", t);
        assert!(!decision.emitted);
        assert_eq!(decision.instance_suppressed, None);
        assert_eq!(decision.global_suppressed, None);
    }
    assert_eq!(
        ferrum_edge::_test_support::udp_rate_limiting_rejection_warn_suppressed_count_for_test(
            &plugin
        ),
        999,
        "per-instance suppressed accounting must retain every in-window rejection"
    );
    assert_eq!(
        ferrum_edge::_test_support::atomic_log_rate_limiter_suppressed_count_for_test(&global),
        999,
        "global suppressed accounting must retain every in-window rejection"
    );

    let rollover = record_rejection_warn(&plugin, &global, "datagram_count", "proxy-1", 1_000);
    assert!(rollover.emitted, "window rollover must emit a summary");
    assert_eq!(rollover.instance_suppressed, Some(999));
    assert_eq!(rollover.global_suppressed, Some(999));
}

#[tokio::test]
async fn datagram_and_byte_limit_rejections_share_bounded_diagnostics() {
    let count_plugin = make_plugin(json!({"datagrams_per_second": 1}));
    let byte_plugin = make_plugin(json!({"bytes_per_second": 100}));

    let mut ctx = make_ctx("10.0.0.1", 50);
    assert_eq!(
        count_plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
    ctx.direction = UdpDatagramDirection::BackendToClient;
    assert_eq!(
        count_plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Drop
    );

    let mut byte_ctx = make_ctx("10.0.0.2", 200);
    assert_eq!(
        byte_plugin.on_udp_datagram(&byte_ctx).await,
        UdpDatagramVerdict::Drop
    );
    byte_ctx.direction = UdpDatagramDirection::BackendToClient;
    assert_eq!(
        byte_plugin.on_udp_datagram(&byte_ctx).await,
        UdpDatagramVerdict::Drop
    );

    let global = rejection_warn_global();
    reset_udp_rejection_warn_state(&count_plugin);
    reset_udp_rejection_warn_state(&byte_plugin);
    let mut count_emissions = 0usize;
    let mut byte_emissions = 0usize;
    for t in 0..5_000 {
        if record_rejection_warn(&count_plugin, &global, "datagram_count", "proxy-1", t).emitted {
            count_emissions += 1;
        }
        if record_rejection_warn(&byte_plugin, &global, "byte_count", "proxy-1", t).emitted {
            byte_emissions += 1;
        }
    }
    assert!(
        count_emissions <= 6,
        "count-limit diagnostics stayed bounded across flood: {count_emissions}"
    );
    assert!(
        byte_emissions <= 6,
        "byte-limit diagnostics stayed bounded across flood: {byte_emissions}"
    );
}

#[test]
fn multiple_plugin_instances_each_emit_independently_with_global_ceiling() {
    let plugin_a = make_plugin(json!({"datagrams_per_second": 1}));
    let plugin_b = make_plugin(json!({"datagrams_per_second": 1}));
    let global = rejection_warn_global();
    reset_udp_rejection_warn_state(&plugin_a);
    reset_udp_rejection_warn_state(&plugin_b);

    assert!(record_rejection_warn(&plugin_a, &global, "datagram_count", "proxy-a", 0).emitted);
    let denied = record_rejection_warn(&plugin_b, &global, "datagram_count", "proxy-b", 0);
    assert!(
        !denied.emitted,
        "global gate must deny the second instance's first rejection in the same window"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_rate_limiting_rejection_warn_suppressed_count_for_test(
            &plugin_b
        ),
        1,
        "denied instance must retain its pending rejection"
    );
    assert_eq!(
        ferrum_edge::_test_support::atomic_log_rate_limiter_suppressed_count_for_test(&global),
        1,
        "global accounting must retain the denied rejection"
    );

    for t in 1..=999 {
        let _ = record_rejection_warn(&plugin_b, &global, "datagram_count", "proxy-b", t);
    }
    assert_eq!(
        ferrum_edge::_test_support::udp_rate_limiting_rejection_warn_suppressed_count_for_test(
            &plugin_b
        ),
        1_000,
        "instance aggregate must carry every rejection through a denied rollover"
    );

    let rollover = record_rejection_warn(&plugin_b, &global, "datagram_count", "proxy-b", 1_000);
    assert!(rollover.emitted);
    assert_eq!(rollover.instance_suppressed, Some(1_000));
    assert_eq!(rollover.global_suppressed, Some(1_000));

    let mut global_emissions = 0usize;
    for t in 1..=10_000 {
        if record_rejection_warn(&plugin_a, &global, "datagram_count", "proxy-a", t).emitted {
            global_emissions += 1;
        }
        if record_rejection_warn(&plugin_b, &global, "datagram_count", "proxy-b", t).emitted {
            global_emissions += 1;
        }
    }
    assert!(
        global_emissions <= 12,
        "global + per-instance bounds must cap warnings across instances: {global_emissions}"
    );
}

#[test]
fn concurrent_rejection_warns_stay_bounded_with_preserved_accounting() {
    use std::sync::Arc;
    use std::thread;

    let plugin = Arc::new(make_plugin(json!({"datagrams_per_second": 1})));
    let global = Arc::new(rejection_warn_global());
    reset_udp_rejection_warn_state(&plugin);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let plugin = Arc::clone(&plugin);
        let global = Arc::clone(&global);
        handles.push(thread::spawn(move || {
            let mut emissions = 0usize;
            let mut instance_reported = 0u64;
            let mut global_reported = 0u64;
            for _ in 0..2_000 {
                let decision =
                    record_rejection_warn(&plugin, &global, "datagram_count", "proxy-1", 1_000);
                if decision.emitted {
                    emissions += 1;
                    instance_reported =
                        instance_reported.saturating_add(decision.instance_suppressed.unwrap_or(0));
                    global_reported =
                        global_reported.saturating_add(decision.global_suppressed.unwrap_or(0));
                }
            }
            (emissions, instance_reported, global_reported)
        }));
    }

    let (emissions, instance_reported, global_reported) = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .fold((0usize, 0u64, 0u64), |acc, result| {
            (
                acc.0 + result.0,
                acc.1.saturating_add(result.1),
                acc.2.saturating_add(result.2),
            )
        });
    assert_eq!(
        emissions, 1,
        "identical timestamps within one window must emit at most once per instance"
    );
    assert_eq!(
        instance_reported
            + ferrum_edge::_test_support::udp_rate_limiting_rejection_warn_suppressed_count_for_test(
                &plugin,
            ),
        (8 * 2_000 - 1) as u64,
        "reported plus pending instance accounting must cover every suppressed rejection"
    );
    assert_eq!(
        global_reported
            + ferrum_edge::_test_support::atomic_log_rate_limiter_suppressed_count_for_test(
                &global
            ),
        (8 * 2_000 - 1) as u64,
        "reported plus pending global accounting must cover every suppressed rejection"
    );
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

// ── Mapped/native UDP identity equivalence (GHSA-vjwj-657f-5w9g) ───────────

/// The byte budget is keyed by the same canonical session identity as the
/// datagram-count budget, so a dual-stack `[::]` listener cannot hand one
/// source two byte allowances.
#[tokio::test]
async fn mapped_ipv4_shares_native_client_byte_budget() {
    let plugin = make_plugin(json!({
        "datagrams_per_second": 1000,
        "bytes_per_second": 150
    }));

    let native = make_ctx("192.0.2.10", 100);
    assert_eq!(
        plugin.on_udp_datagram(&native).await,
        UdpDatagramVerdict::Forward
    );

    // 100 + 100 > 150 only if both datagrams counted against one budget.
    let mapped = make_ctx("::ffff:192.0.2.10", 100);
    assert_eq!(
        plugin.on_udp_datagram(&mapped).await,
        UdpDatagramVerdict::Drop
    );
    assert_eq!(plugin.tracked_keys_count(), Some(1));
}

/// Redis-configured enforcement derives its key from the same canonical session
/// identity (`ip:{client_ip}`). With Redis unreachable the default
/// `fail_closed` policy would drop every datagram, which cannot distinguish a
/// shared principal from a blanket outage refusal. Opt into `local_fallback`
/// so the local map is the enforcement surface — exactly where a divergent
/// key would show up as two tracked entries and a second free budget.
#[tokio::test]
async fn redis_mode_shares_one_budget_across_representations() {
    let plugin = make_plugin(json!({
        "datagrams_per_second": 1,
        "bytes_per_second": 150,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:9/0",
        "redis_health_check_interval_seconds": 1,
        "redis_failure_policy": "local_fallback"
    }));

    let native = make_ctx("192.0.2.10", 100);
    assert_eq!(
        plugin.on_udp_datagram(&native).await,
        UdpDatagramVerdict::Forward
    );

    let mapped = make_ctx("::ffff:192.0.2.10", 100);
    assert_eq!(
        plugin.on_udp_datagram(&mapped).await,
        UdpDatagramVerdict::Drop,
        "the Redis-mode key must name one principal for both representations"
    );
    assert_eq!(plugin.tracked_keys_count(), Some(1));

    // Non-vacuity: a genuinely different source is still admitted, so the drop
    // above is the shared budget and not a blanket Redis-outage rejection.
    let other = make_ctx("198.51.100.7", 100);
    assert_eq!(
        plugin.on_udp_datagram(&other).await,
        UdpDatagramVerdict::Forward
    );
    assert_eq!(plugin.tracked_keys_count(), Some(2));
}

/// True IPv6 sources keep their own budgets — the fold must not reach beyond
/// the `::ffff:0:0/96` mapped range.
#[tokio::test]
async fn true_ipv6_sources_keep_independent_budgets() {
    let plugin = make_plugin(json!({"datagrams_per_second": 1}));

    for client_ip in [
        "192.0.2.10",
        "::192.0.2.10",
        "64:ff9b::c000:20a",
        "2001:db8::10",
    ] {
        assert_eq!(
            plugin.on_udp_datagram(&make_ctx(client_ip, 10)).await,
            UdpDatagramVerdict::Forward,
            "each distinct network identity gets its own budget: {client_ip}"
        );
    }
    assert_eq!(plugin.tracked_keys_count(), Some(4));

    // The mapped form is the one and only alias of the native IPv4 source.
    assert_eq!(
        plugin
            .on_udp_datagram(&make_ctx("::ffff:192.0.2.10", 10))
            .await,
        UdpDatagramVerdict::Drop
    );
    assert_eq!(plugin.tracked_keys_count(), Some(4));
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [
        (
            json!({"datagrams_per_second": "'UNREGISTERED_TRAFFIC_TOKEN"}),
            "`datagrams_per_second`",
            "must be an integer",
        ),
        (
            json!({"datagrams_per_second": true}),
            "`datagrams_per_second`",
            "must be an integer",
        ),
    ] {
        let error = ferrum_edge::plugins::validate_plugin_config("udp_rate_limiting", &config)
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
fn shared_window_bound_keeps_udp_plugin_and_field_when_rendered() {
    use ferrum_edge::plugins::utils::rate_limit::MAX_RATE_LIMIT_WINDOW_SECONDS;

    let value = MAX_RATE_LIMIT_WINDOW_SECONDS + 1;
    let config = json!({"datagrams_per_second": 1, "window_seconds": value});
    let error = ferrum_edge::plugins::validate_plugin_config("udp_rate_limiting", &config)
        .expect_err("an excessive window must fail the shared bound");
    let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
    assert!(rendered.starts_with("udp_rate_limiting:"), "{rendered}");
    assert!(rendered.contains("`window_seconds`"), "{rendered}");
    assert!(
        rendered.contains(&format!(
            "must be <= {MAX_RATE_LIMIT_WINDOW_SECONDS} seconds"
        )),
        "{rendered}"
    );
    assert!(!rendered.contains(&value.to_string()), "{rendered}");
}

// ── Production-launch review fixes ─────────────────────────────────────

/// SOL-1: admission never lets the map grow PAST the cap, so a map that is
/// exactly full of clients that have all gone idle must reopen through the
/// ordinary per-datagram cleanup path — without waiting for (or arming) the
/// 100,000-hook periodic sample.
#[test]
fn full_map_of_expired_clients_reopens_without_a_periodic_sample() {
    use ferrum_edge::_test_support::RateLimitCleanupHarness;
    use std::time::Duration;

    let h = RateLimitCleanupHarness::new();
    let epoch = h.udp_epoch_base();
    let cap = 2;
    assert!(h.seed_udp_with_cap("10.0.0.1", epoch, cap));
    assert!(h.seed_udp_with_cap("10.0.0.2", epoch, cap));
    assert!(
        !h.seed_udp_with_cap("10.0.0.3", epoch, cap),
        "a full map refuses a previously unseen client"
    );

    // Idle threshold is max(window_seconds * 2, 10) == 10s for window=1.
    let idle = epoch + Duration::from_secs(11);
    let _ = h.maybe_evict_udp_at_with_cap(idle, cap);
    assert_eq!(
        h.udp_tracked(),
        Some(0),
        "a full map of expired clients must be reclaimed at the cap, not only above it"
    );
    assert!(
        h.seed_udp_with_cap("10.0.0.3", idle, cap),
        "a new client is admitted once the stale entries are reclaimed"
    );
}

/// SOL-1 control: at the cap, live budgets are never force-evicted.
#[test]
fn full_map_of_active_clients_stays_closed_to_new_clients() {
    use ferrum_edge::_test_support::RateLimitCleanupHarness;
    use std::time::Duration;

    let h = RateLimitCleanupHarness::new();
    let epoch = h.udp_epoch_base();
    let cap = 2;
    let active = epoch + Duration::from_secs(20);
    assert!(h.seed_udp_with_cap("10.0.0.1", active, cap));
    assert!(h.seed_udp_with_cap("10.0.0.2", active, cap));

    let _ = h.maybe_evict_udp_at_with_cap(active + Duration::from_secs(1), cap);
    assert_eq!(h.udp_tracked(), Some(2));
    assert!(h.udp_contains("10.0.0.1"));
    assert!(h.udp_contains("10.0.0.2"));
    assert!(!h.seed_udp_with_cap("10.0.0.3", active, cap));
}

/// SOL-1 on the Redis-fallback map, which shares the admission and cleanup
/// path.
#[tokio::test]
async fn full_redis_fallback_map_of_expired_clients_reopens() {
    use ferrum_edge::_test_support::{
        udp_rate_limiting_contains_client_for_test, udp_rate_limiting_epoch_base_for_test,
        udp_rate_limiting_maybe_evict_at_with_cap_for_test,
        udp_rate_limiting_seed_client_at_with_cap_for_test,
    };
    use std::time::Duration;

    let plugin = make_plugin(json!({
        "datagrams_per_second": 1_000,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:9/0",
        "redis_health_check_interval_seconds": 1,
        "redis_failure_policy": "local_fallback"
    }));
    let epoch = udp_rate_limiting_epoch_base_for_test(&plugin);
    let cap = 2;
    assert!(udp_rate_limiting_seed_client_at_with_cap_for_test(
        &plugin, "10.0.0.1", epoch, cap
    ));
    assert!(udp_rate_limiting_seed_client_at_with_cap_for_test(
        &plugin, "10.0.0.2", epoch, cap
    ));
    assert!(!udp_rate_limiting_seed_client_at_with_cap_for_test(
        &plugin, "10.0.0.3", epoch, cap
    ));

    let idle = epoch + Duration::from_secs(11);
    let _ = udp_rate_limiting_maybe_evict_at_with_cap_for_test(&plugin, idle, cap);
    assert_eq!(plugin.tracked_keys_count(), Some(0));
    assert!(!udp_rate_limiting_contains_client_for_test(
        &plugin, "10.0.0.1"
    ));
    assert!(udp_rate_limiting_seed_client_at_with_cap_for_test(
        &plugin, "10.0.0.3", idle, cap
    ));
}

/// SOL-2: steady in-window admission of an existing client decides through a
/// shared shard reference; only the first insert takes the exclusive entry
/// guard. (The counter is compiled only with `debug_assertions`; in a release
/// test build it reads zero and the assertion is vacuous.)
#[tokio::test]
async fn steady_existing_client_admission_skips_the_exclusive_entry_guard() {
    use ferrum_edge::_test_support::udp_rate_limiting_exclusive_entry_calls_for_test;

    // One long window so the loop cannot cross a rollover.
    let plugin = make_plugin(json!({"datagrams_per_second": 1_000, "window_seconds": 3_600}));
    let ctx = make_ctx("10.0.0.1", 64);
    assert_eq!(
        plugin.on_udp_datagram(&ctx).await,
        UdpDatagramVerdict::Forward
    );
    let after_insert = udp_rate_limiting_exclusive_entry_calls_for_test(&plugin);
    for _ in 0..1_000 {
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }
    assert_eq!(
        udp_rate_limiting_exclusive_entry_calls_for_test(&plugin),
        after_insert,
        "steady occupied-key admission must not take the exclusive shard guard"
    );
}

/// SOL-2: the shared fast path keeps exact accounting under concurrency, and a
/// window rollover reached by many threads at once resets exactly once.
#[test]
fn concurrent_same_client_admission_and_rollover_never_over_admit() {
    use ferrum_edge::plugins::utils::rate_limit::{
        LocalLimiter, UdpRateLimitAlgorithm, UdpRateLimitOp,
    };
    use std::time::{Duration, Instant};

    let epoch = Instant::now();
    let limit = 100u64;
    let limiter = Arc::new(LocalLimiter::new(
        UdpRateLimitAlgorithm::new(Some(limit), None, 10, epoch),
        4,
    ));
    let op = UdpRateLimitOp { datagram_size: 1 };
    let window_zero = epoch + Duration::from_secs(1);
    let window_one = epoch + Duration::from_secs(11);

    let run = |at: Instant| -> u64 {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                std::thread::spawn(move || {
                    (0..50)
                        .filter(|_| limiter.check_at("10.0.0.1".to_string(), &op, at).allowed)
                        .count() as u64
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("worker joins"))
            .sum()
    };

    assert_eq!(
        run(window_zero),
        limit,
        "400 concurrent attempts in one window admit exactly the limit"
    );
    assert_eq!(
        run(window_one),
        limit,
        "a rollover raced by every thread resets once and admits exactly the limit"
    );
}

/// M5: `ipv6_prefix` widens IPv6 grouping; the default stays `/64`.
#[tokio::test]
async fn ipv6_prefix_groups_addresses_across_a_wider_prefix() {
    // 3600-byte window budget, one 3600-byte datagram per client: a second
    // datagram on the same budget is dropped.
    let base = json!({"bytes_per_second": 1, "window_seconds": 3_600});
    let mut wide = base.clone();
    wide["ipv6_prefix"] = json!(56);

    let default_prefix = make_plugin(base);
    let wide_prefix = make_plugin(wide);
    // Same /56, different /64.
    let first = make_ctx("2001:db8:0:1::1", 3_600);
    let second = make_ctx("2001:db8:0:2::1", 3_600);

    assert_eq!(
        default_prefix.on_udp_datagram(&first).await,
        UdpDatagramVerdict::Forward
    );
    assert_eq!(
        default_prefix.on_udp_datagram(&second).await,
        UdpDatagramVerdict::Forward,
        "default /64 grouping keeps distinct /64s independent"
    );

    assert_eq!(
        wide_prefix.on_udp_datagram(&first).await,
        UdpDatagramVerdict::Forward
    );
    assert_eq!(
        wide_prefix.on_udp_datagram(&second).await,
        UdpDatagramVerdict::Drop,
        "ipv6_prefix: 56 folds both /64s into one budget"
    );
    assert_eq!(wide_prefix.tracked_keys_count(), Some(1));

    // IPv4 stays host-keyed regardless of the IPv6 prefix.
    assert_eq!(
        wide_prefix
            .on_udp_datagram(&make_ctx("192.0.2.1", 3_600))
            .await,
        UdpDatagramVerdict::Forward
    );
    assert_eq!(
        wide_prefix
            .on_udp_datagram(&make_ctx("192.0.2.2", 3_600))
            .await,
        UdpDatagramVerdict::Forward
    );
}

/// M4: the session hands hooks a typed canonical address computed once, so a
/// mapped IPv4 peer and its native form are one typed identity.
#[test]
fn session_typed_client_address_is_canonical() {
    let mapped: std::net::SocketAddr = "[::ffff:192.0.2.10]:5353".parse().unwrap();
    assert_eq!(
        ferrum_edge::proxy::udp_proxy::udp_session_client_addr(mapped),
        "192.0.2.10".parse::<std::net::IpAddr>().unwrap()
    );
    let native: std::net::SocketAddr = "[2001:db8::10]:5353".parse().unwrap();
    assert_eq!(
        ferrum_edge::proxy::udp_proxy::udp_session_client_addr(native),
        "2001:db8::10".parse::<std::net::IpAddr>().unwrap()
    );
}

/// M8: a one-direction policy limits that direction and neither counts nor
/// drops the other; the default still shares one budget.
#[tokio::test]
async fn direction_scopes_what_is_counted_and_limited() {
    let ingress = make_plugin(json!({
        "datagrams_per_second": 2,
        "window_seconds": 3_600,
        "direction": "client_to_backend"
    }));
    let mut reply = make_ctx("10.0.0.1", 10);
    reply.direction = UdpDatagramDirection::BackendToClient;
    for _ in 0..20_000 {
        assert_eq!(
            ingress.on_udp_datagram(&reply).await,
            UdpDatagramVerdict::Forward,
            "replies are outside a client_to_backend budget"
        );
    }
    assert_eq!(
        ingress.tracked_keys_count(),
        Some(0),
        "an out-of-scope direction creates no state"
    );
    let request = make_ctx("10.0.0.1", 10);
    for _ in 0..7_200 {
        assert_eq!(
            ingress.on_udp_datagram(&request).await,
            UdpDatagramVerdict::Forward
        );
    }
    assert_eq!(
        ingress.on_udp_datagram(&request).await,
        UdpDatagramVerdict::Drop,
        "requests are still limited"
    );
    assert_eq!(
        ingress.on_udp_datagram(&reply).await,
        UdpDatagramVerdict::Forward,
        "an exhausted request budget never drops replies"
    );

    let egress = make_plugin(json!({
        "datagrams_per_second": 1,
        "window_seconds": 3_600,
        "direction": "backend_to_client"
    }));
    for _ in 0..3_600 {
        assert_eq!(
            egress.on_udp_datagram(&reply).await,
            UdpDatagramVerdict::Forward
        );
    }
    assert_eq!(
        egress.on_udp_datagram(&reply).await,
        UdpDatagramVerdict::Drop
    );
    assert_eq!(
        egress.on_udp_datagram(&request).await,
        UdpDatagramVerdict::Forward
    );
}

#[test]
fn ipv6_prefix_and_direction_admission_rules() {
    for config in [
        json!({"datagrams_per_second": 1, "ipv6_prefix": 0}),
        json!({"datagrams_per_second": 1, "ipv6_prefix": 129}),
        json!({"datagrams_per_second": 1, "ipv6_prefix": "64"}),
        json!({"datagrams_per_second": 1, "ipv6_prefix": null}),
        json!({"datagrams_per_second": 1, "ipv6_prefix": -1}),
        json!({"datagrams_per_second": 1, "direction": "inbound"}),
        json!({"datagrams_per_second": 1, "direction": "BOTH"}),
        json!({"datagrams_per_second": 1, "direction": null}),
        json!({"datagrams_per_second": 1, "direction": 1}),
    ] {
        assert!(
            ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
                &config,
                PluginHttpClient::default(),
            )
            .is_err(),
            "must be rejected: {config}"
        );
    }
    for config in [
        json!({"datagrams_per_second": 1, "ipv6_prefix": 1}),
        json!({"datagrams_per_second": 1, "ipv6_prefix": 128}),
        json!({"datagrams_per_second": 1, "direction": "both"}),
        json!({"datagrams_per_second": 1, "direction": "client_to_backend"}),
        json!({"datagrams_per_second": 1, "direction": "backend_to_client"}),
    ] {
        assert!(
            ferrum_edge::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
                &config,
                PluginHttpClient::default(),
            )
            .is_ok(),
            "must be accepted: {config}"
        );
    }
}

/// M7: under the default `fail_closed` policy a Redis outage drop is counted on
/// the dedicated enforcement-unavailable counter, never as a client over-limit.
#[tokio::test]
async fn fail_closed_outage_drop_is_counted_as_enforcement_unavailable() {
    let plugin = make_plugin(json!({
        "datagrams_per_second": 1_000,
        "sync_mode": "redis",
        "redis_url": "redis://127.0.0.1:9/0",
        "redis_connect_timeout_seconds": 1,
        "redis_health_check_interval_seconds": 1
    }));
    let registry = ferrum_edge::plugins::prometheus_metrics::global_registry();
    let before = registry
        .rate_limit_unavailable_denials
        .load(Ordering::Relaxed);
    assert_eq!(
        plugin.on_udp_datagram(&make_ctx("10.0.0.1", 10)).await,
        UdpDatagramVerdict::Drop,
        "an unreachable store fails closed"
    );
    assert!(
        registry
            .rate_limit_unavailable_denials
            .load(Ordering::Relaxed)
            > before,
        "the outage drop must be counted"
    );
}
