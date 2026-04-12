//! Tests for DNS cache and resolution module

use ferrum_edge::dns::{DnsCache, DnsConfig};
use std::collections::HashMap;

/// Helper to create a default DnsConfig with custom overrides.
fn default_dns_config(overrides: HashMap<String, String>) -> DnsConfig {
    DnsConfig {
        global_overrides: overrides,
        ..DnsConfig::default()
    }
}

// ============================================================================
// Core resolution tests
// ============================================================================

#[tokio::test]
async fn test_dns_cache_creation() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    // Cache should be functional after creation — verify by resolving a loopback IP
    let result = cache.resolve("127.0.0.1", None, None).await;
    assert!(
        result.is_ok(),
        "Newly created cache should resolve IPs immediately"
    );
    assert_eq!(result.unwrap().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_dns_resolve_ip_address_directly() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // Resolving a literal IP address should return it directly
    let result = cache.resolve("127.0.0.1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_dns_resolve_ipv6_directly() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache.resolve("::1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "::1");
}

#[tokio::test]
async fn test_dns_per_proxy_override() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // Per-proxy override should be used first
    let result = cache.resolve("example.com", Some("10.0.0.1"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.1");
}

#[tokio::test]
async fn test_dns_global_override() {
    let mut overrides = HashMap::new();
    overrides.insert("myhost.local".to_string(), "192.168.1.100".to_string());
    let cache = DnsCache::new(default_dns_config(overrides));

    let result = cache.resolve("myhost.local", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "192.168.1.100");
}

#[tokio::test]
async fn test_dns_per_proxy_override_takes_precedence_over_global() {
    let mut overrides = HashMap::new();
    overrides.insert("myhost.local".to_string(), "192.168.1.100".to_string());
    let cache = DnsCache::new(default_dns_config(overrides));

    // Per-proxy override should take precedence over global
    let result = cache.resolve("myhost.local", Some("10.0.0.5"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.5");
}

#[tokio::test]
async fn test_dns_invalid_override_ip() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // Invalid IP override should return an error
    let result = cache.resolve("example.com", Some("not-an-ip"), None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_resolve_localhost() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    // localhost should resolve to 127.0.0.1 or ::1
    assert!(addr.to_string() == "127.0.0.1" || addr.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_caching_returns_same_result() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // First resolution
    let result1 = cache.resolve("localhost", None, None).await.unwrap();
    // Second resolution should use cache
    let result2 = cache.resolve("localhost", None, None).await.unwrap();

    assert_eq!(result1, result2);
}

#[tokio::test]
async fn test_dns_warmup_does_not_panic() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let hostnames = vec![
        ("localhost".to_string(), None, None),
        ("127.0.0.1".to_string(), None, None),
        ("nonexistent.invalid".to_string(), None, None), // Should warn but not panic
    ];

    cache.warmup(hostnames).await;
}

#[tokio::test]
async fn test_dns_warmup_with_overrides() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let hostnames = vec![(
        "myhost.local".to_string(),
        Some("10.0.0.1".to_string()),
        Some(600),
    )];

    cache.warmup(hostnames).await;

    // After warmup, the resolved IP should be cached
    let result = cache.resolve("myhost.local", Some("10.0.0.1"), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_custom_ttl_per_proxy() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // Resolve with custom per-proxy TTL
    let result = cache.resolve("localhost", None, Some(60)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_resolve_nonexistent_domain() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache
        .resolve("this-domain-absolutely-does-not-exist.invalid", None, None)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_cache_len_starts_empty() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    assert_eq!(cache.cache_len(), 0);
}

#[tokio::test]
async fn test_dns_warmup_populates_cache() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    assert_eq!(cache.cache_len(), 0);

    let hostnames = vec![
        ("localhost".to_string(), None, None),
        ("127.0.0.1".to_string(), None, None),
    ];
    cache.warmup(hostnames).await;

    // After warmup, cache should contain entries for resolved hostnames
    assert!(
        cache.cache_len() >= 1,
        "Warmup should populate at least one cache entry"
    );
}

#[tokio::test]
async fn test_dns_ttl_expiration_causes_re_resolution() {
    // Use a very short min_ttl and stale TTL so entries expire quickly
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    // First resolution populates cache with per-proxy TTL of 1s
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for TTL + stale_ttl to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Second resolution should still succeed (re-resolves from DNS)
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(
        result1, result2,
        "Re-resolution should return same IP for localhost"
    );
}

#[tokio::test]
async fn test_dns_concurrent_resolution_safety() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    let mut handles = Vec::new();

    // Spawn 100 concurrent resolutions for the same host
    for _ in 0..100 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            cache.resolve("localhost", None, None).await
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(
            result.is_ok(),
            "Concurrent resolution should not panic or error"
        );
        results.push(result.unwrap());
    }

    // All should resolve to the same IP
    let first = results[0];
    for ip in &results {
        assert_eq!(
            *ip, first,
            "All concurrent resolutions should return the same IP"
        );
    }
}

#[tokio::test]
async fn test_dns_per_proxy_override_bypasses_cache() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // Resolve with override — should NOT populate cache
    let result = cache
        .resolve("some-host.example.com", Some("10.0.0.1"), None)
        .await
        .unwrap();
    assert_eq!(result.to_string(), "10.0.0.1");

    // Cache should be empty since overrides bypass caching
    assert_eq!(
        cache.cache_len(),
        0,
        "Per-proxy override should bypass cache"
    );
}

#[tokio::test]
async fn test_dns_cache_serves_from_cache_within_ttl() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // First call populates cache
    let _result1 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Second call should use cache (no way to directly verify but we can
    // confirm it returns immediately and gives same result)
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(
        cache.cache_len(),
        1,
        "Cache should still have exactly 1 entry"
    );
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
}

// ============================================================================
// Error caching tests
// ============================================================================

#[tokio::test]
async fn test_dns_error_caching() {
    let cache = DnsCache::new(DnsConfig {
        error_ttl_seconds: 5,
        ..DnsConfig::default()
    });

    // First resolution of non-existent domain should fail
    let result1 = cache
        .resolve("this-domain-absolutely-does-not-exist.invalid", None, None)
        .await;
    assert!(result1.is_err(), "First resolution should fail");

    // Error should be cached
    assert!(
        cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"),
        "Error should be cached"
    );

    // Second resolution should return cached error immediately
    let result2 = cache
        .resolve("this-domain-absolutely-does-not-exist.invalid", None, None)
        .await;
    assert!(
        result2.is_err(),
        "Second resolution should also fail (cached error)"
    );
}

#[tokio::test]
async fn test_dns_error_ttl_expiration() {
    let cache = DnsCache::new(DnsConfig {
        error_ttl_seconds: 1,
        ..DnsConfig::default()
    });

    // Resolve a non-existent domain
    let _ = cache
        .resolve("this-domain-absolutely-does-not-exist.invalid", None, None)
        .await;
    assert!(cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"));

    // Wait for error TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Cached error should have expired
    assert!(
        !cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"),
        "Cached error should expire after error_ttl"
    );
}

// ============================================================================
// Stale-while-revalidate tests
// ============================================================================

#[tokio::test]
async fn test_dns_stale_while_revalidate() {
    // Short TTL with stale window, using per-proxy TTL to force 1s expiry
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 10,
        ..DnsConfig::default()
    });

    // First resolution populates cache with 1s per-proxy TTL
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for TTL to expire but stay within stale window
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Should return stale data (and trigger background refresh)
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(
        result1, result2,
        "Stale data should be returned during stale window"
    );

    // Give background refresh time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Cache should have been refreshed
    assert_eq!(
        cache.cache_len(),
        1,
        "Cache should still have the entry after refresh"
    );
}

#[tokio::test]
async fn test_dns_stale_deadline_enforcement() {
    // Very short TTL and very short stale TTL
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 1,
        ..DnsConfig::default()
    });

    // First resolution with per-proxy TTL override
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for both TTL and stale_ttl to expire (1 + 1 = 2 seconds)
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Should re-resolve (not serve stale data since we're past stale_deadline)
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(
        result1, result2,
        "Re-resolution should return same IP for localhost"
    );
}

// ============================================================================
// Native TTL respect tests (new behavior)
// ============================================================================

#[tokio::test]
async fn test_dns_default_config_has_no_ttl_override() {
    // The default config should NOT have a global TTL override — native TTL is respected
    let config = DnsConfig::default();
    assert!(
        config.ttl_override_seconds.is_none(),
        "Default config should not override TTL — native record TTL should be respected"
    );
    assert_eq!(config.min_ttl_seconds, 5, "Default min TTL should be 5s");
}

#[tokio::test]
async fn test_dns_global_ttl_override() {
    // When ttl_override_seconds is set, all entries use that TTL
    let cache = DnsCache::new(DnsConfig {
        ttl_override_seconds: Some(1),
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    // Resolve populates cache
    let _result = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for the overridden TTL (1 second) to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Entry should have expired (ttl_override=1s has passed, stale_ttl=0)
    // A fresh resolve should succeed via re-resolution
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_per_proxy_ttl_overrides_global() {
    // Per-proxy TTL should take precedence over global TTL override
    let cache = DnsCache::new(DnsConfig {
        ttl_override_seconds: Some(3600), // global: 1 hour
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    // Resolve with per-proxy TTL of 1 second
    let _result = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for per-proxy TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Entry should have expired despite global TTL being 3600s
    // because per-proxy TTL (1s) takes precedence
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_min_ttl_floor_prevents_zero_ttl() {
    // Even with no override, min_ttl should prevent entries from having zero TTL
    let cache = DnsCache::new(DnsConfig {
        ttl_override_seconds: None,
        min_ttl_seconds: 2,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    // Resolve — even if native TTL is very short, min_ttl clamps it to 2s
    let _result = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // After 1 second, the entry should still be fresh (min_ttl = 2s)
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
    // Still 1 entry, confirming it was served from cache
    assert_eq!(cache.cache_len(), 1);
}

#[tokio::test]
async fn test_dns_min_ttl_clamps_per_proxy_ttl() {
    // Per-proxy TTL of 1s should be clamped up to min_ttl of 3s
    let cache = DnsCache::new(DnsConfig {
        ttl_override_seconds: None,
        min_ttl_seconds: 3,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    let _result = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // After 2 seconds, per-proxy TTL of 1s would have expired, but min_ttl
    // clamped it to 3s so the entry is still fresh
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
    assert_eq!(cache.cache_len(), 1);
}

// ============================================================================
// DNS record order tests
// ============================================================================

#[tokio::test]
async fn test_dns_order_default() {
    // Default order is CACHE,SRV,A,CNAME — A should resolve localhost
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok(), "Default DNS order should resolve localhost");
}

#[tokio::test]
async fn test_dns_order_a_only() {
    let cache = DnsCache::new(DnsConfig {
        dns_order: Some("A".to_string()),
        ..DnsConfig::default()
    });

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok(), "A-only DNS order should resolve localhost");
    // With A-only order, should get IPv4
    let addr = result.unwrap();
    assert!(addr.is_ipv4(), "A-only order should return IPv4 address");
}

#[tokio::test]
async fn test_dns_order_aaaa_only() {
    let cache = DnsCache::new(DnsConfig {
        dns_order: Some("AAAA".to_string()),
        ..DnsConfig::default()
    });

    let result = cache.resolve("localhost", None, None).await;
    // AAAA may or may not succeed depending on system config
    // Just verify it doesn't panic
    let _ = result;
}

#[tokio::test]
async fn test_dns_order_case_insensitive() {
    // dns_order should be case-insensitive
    let cache = DnsCache::new(DnsConfig {
        dns_order: Some("cache,a,aaaa,cname".to_string()),
        ..DnsConfig::default()
    });

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok(), "Case-insensitive DNS order should work");
}

// ============================================================================
// Custom hosts file tests
// ============================================================================

#[tokio::test]
async fn test_dns_custom_hosts_file() {
    use std::io::Write;

    // Create a temporary hosts file
    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("test_hosts");
    {
        let mut f = std::fs::File::create(&hosts_path).unwrap();
        writeln!(f, "10.99.99.1  my-custom-host.test").unwrap();
        writeln!(f, "10.99.99.2  another-host.test").unwrap();
    }

    let cache = DnsCache::new(DnsConfig {
        hosts_file_path: Some(hosts_path.to_str().unwrap().to_string()),
        ..DnsConfig::default()
    });

    // The custom hosts file entry should be resolvable
    let result = cache.resolve("my-custom-host.test", None, None).await;
    assert!(
        result.is_ok(),
        "Custom hosts file entry should resolve: {:?}",
        result
    );
    assert_eq!(result.unwrap().to_string(), "10.99.99.1");

    let result2 = cache.resolve("another-host.test", None, None).await;
    assert!(result2.is_ok(), "Second custom hosts entry should resolve");
    assert_eq!(result2.unwrap().to_string(), "10.99.99.2");
}

// ============================================================================
// DnsConfig defaults tests
// ============================================================================

#[tokio::test]
async fn test_dns_config_default() {
    let config = DnsConfig::default();
    assert!(
        config.ttl_override_seconds.is_none(),
        "Global TTL override disabled by default"
    );
    assert_eq!(config.min_ttl_seconds, 5);
    assert_eq!(config.stale_ttl_seconds, 3600);
    assert_eq!(config.error_ttl_seconds, 5);
    assert!(config.resolver_addresses.is_none());
    assert!(config.hosts_file_path.is_none());
    assert!(config.dns_order.is_none());
    assert!(config.global_overrides.is_empty());
    assert_eq!(config.warmup_concurrency, 500);
    assert!(
        config.slow_threshold_ms.is_none(),
        "Slow threshold should be disabled by default"
    );
    assert_eq!(config.refresh_threshold_percent, 90);
    assert_eq!(config.failed_retry_interval_seconds, 10);
}

// ============================================================================
// Slow resolution threshold tests
// ============================================================================

#[tokio::test]
async fn test_dns_slow_threshold_disabled_by_default() {
    let cache = DnsCache::new(DnsConfig {
        slow_threshold_ms: None,
        ..DnsConfig::default()
    });

    let result = cache.resolve("127.0.0.1", None, None).await;
    assert!(
        result.is_ok(),
        "Resolution should work with threshold disabled"
    );
    assert_eq!(result.unwrap().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_dns_slow_threshold_does_not_affect_resolution_result() {
    let cache = DnsCache::new(DnsConfig {
        slow_threshold_ms: Some(0),
        ..DnsConfig::default()
    });

    let result = cache.resolve("localhost", None, None).await;
    assert!(
        result.is_ok(),
        "Resolution should succeed regardless of slow threshold"
    );
    let addr = result.unwrap();
    assert!(addr.to_string() == "127.0.0.1" || addr.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_slow_threshold_high_value_no_warn() {
    let cache = DnsCache::new(DnsConfig {
        slow_threshold_ms: Some(60_000),
        ..DnsConfig::default()
    });

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok(), "Resolution should work with high threshold");
}

#[tokio::test]
async fn test_dns_slow_threshold_with_cached_entries() {
    let cache = DnsCache::new(DnsConfig {
        slow_threshold_ms: Some(0),
        ..DnsConfig::default()
    });

    let result1 = cache.resolve("localhost", None, None).await.unwrap();
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(result1, result2, "Cached result should match");
}

#[tokio::test]
async fn test_dns_slow_threshold_with_overrides() {
    let cache = DnsCache::new(DnsConfig {
        slow_threshold_ms: Some(0),
        ..DnsConfig::default()
    });

    let result = cache.resolve("example.com", Some("10.0.0.1"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.1");
}

#[tokio::test]
async fn test_dns_slow_threshold_on_error() {
    let cache = DnsCache::new(DnsConfig {
        slow_threshold_ms: Some(0),
        ..DnsConfig::default()
    });

    let result = cache
        .resolve("this-domain-absolutely-does-not-exist.invalid", None, None)
        .await;
    assert!(
        result.is_err(),
        "Resolution of non-existent domain should fail"
    );
}

// ============================================================================
// Refresh threshold tests
// ============================================================================

#[tokio::test]
async fn test_dns_refresh_threshold_default_is_90() {
    let config = DnsConfig::default();
    assert_eq!(config.refresh_threshold_percent, 90);
}

#[tokio::test]
async fn test_dns_refresh_threshold_clamped_to_valid_range() {
    let cache_low = DnsCache::new(DnsConfig {
        refresh_threshold_percent: 0,
        ..DnsConfig::default()
    });
    let result = cache_low.resolve("127.0.0.1", None, None).await;
    assert!(result.is_ok());

    let cache_high = DnsCache::new(DnsConfig {
        refresh_threshold_percent: 100,
        ..DnsConfig::default()
    });
    let result = cache_high.resolve("127.0.0.1", None, None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_refresh_threshold_custom_value() {
    let cache = DnsCache::new(DnsConfig {
        refresh_threshold_percent: 75,
        ..DnsConfig::default()
    });
    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok());
}

// ============================================================================
// resolve_all tests
// ============================================================================

#[tokio::test]
async fn test_dns_resolve_all_returns_all_addresses() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache.resolve_all("localhost", None, None).await;
    assert!(result.is_ok(), "resolve_all should succeed for localhost");
    let ips = result.unwrap();
    assert!(!ips.is_empty(), "resolve_all should return at least one IP");
}

#[tokio::test]
async fn test_dns_resolve_all_per_proxy_override() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache
        .resolve_all("example.com", Some("192.168.1.1"), None)
        .await
        .unwrap();
    assert_eq!(
        result,
        vec!["192.168.1.1".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn test_dns_resolve_all_global_override() {
    let mut overrides = HashMap::new();
    overrides.insert("db.internal".to_string(), "10.0.0.5".to_string());
    let cache = DnsCache::new(default_dns_config(overrides));

    let result = cache.resolve_all("db.internal", None, None).await.unwrap();
    assert_eq!(
        result,
        vec!["10.0.0.5".parse::<std::net::IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn test_dns_resolve_all_caches_entries() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result1 = cache.resolve_all("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    let result2 = cache.resolve_all("localhost", None, None).await.unwrap();
    assert_eq!(result1, result2);
}

// ============================================================================
// Failed retry task tests
// ============================================================================

#[tokio::test]
async fn test_dns_failed_retry_task_disabled_when_zero() {
    let cache = DnsCache::new(DnsConfig {
        failed_retry_interval_seconds: 0,
        ..DnsConfig::default()
    });

    let handle = cache.start_failed_retry_task(None);
    assert!(
        handle.is_none(),
        "Failed retry task should be disabled when interval is 0"
    );
}

#[tokio::test]
async fn test_dns_failed_retry_task_starts_when_enabled() {
    let cache = DnsCache::new(DnsConfig {
        failed_retry_interval_seconds: 10,
        ..DnsConfig::default()
    });

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handle = cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));
    assert!(
        handle.is_some(),
        "Failed retry task should start when interval > 0"
    );

    // Shut it down cleanly
    let _ = shutdown_tx.send(true);
    if let Some(h) = handle {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
async fn test_dns_failed_retry_task_retries_expired_errors() {
    let cache = DnsCache::new(DnsConfig {
        error_ttl_seconds: 1, // 1s error cache — expires quickly
        failed_retry_interval_seconds: 1,
        ..DnsConfig::default()
    });

    // Trigger a DNS error for a non-existent domain
    let _ = cache
        .resolve("this-domain-absolutely-does-not-exist.invalid", None, None)
        .await;
    assert!(cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"));

    // Start the retry task
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handle = cache.start_failed_retry_task(Some(shutdown_tx.subscribe()));

    // Wait for error TTL to expire + retry interval
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // The retry task should have attempted re-resolution (and re-cached the error
    // since the domain still doesn't exist)
    // We can't assert on the retry attempt directly, but we can verify the task
    // is still running and the cache still has the entry
    assert!(
        cache.cache_len() >= 1,
        "Cache should still have the error entry after retry"
    );

    let _ = shutdown_tx.send(true);
    if let Some(h) = handle {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
    }
}

#[tokio::test]
async fn test_dns_failed_retry_task_shuts_down_cleanly() {
    let cache = DnsCache::new(DnsConfig {
        failed_retry_interval_seconds: 1,
        ..DnsConfig::default()
    });

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handle = cache
        .start_failed_retry_task(Some(shutdown_tx.subscribe()))
        .unwrap();

    // Let it run for a tick
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send shutdown signal
    let _ = shutdown_tx.send(true);

    // Task should complete within a reasonable time
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
    assert!(result.is_ok(), "Failed retry task should shut down cleanly");
}
