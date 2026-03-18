//! Tests for DNS cache and resolution module

use ferrum_gateway::dns::{DnsCache, DnsConfig};
use std::collections::HashMap;

/// Helper to create a default DnsConfig with custom TTL and overrides.
fn default_dns_config(ttl: u64, overrides: HashMap<String, String>) -> DnsConfig {
    DnsConfig {
        default_ttl_seconds: ttl,
        global_overrides: overrides,
        ..DnsConfig::default()
    }
}

#[tokio::test]
async fn test_dns_cache_creation() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));
    // Should be able to create a cache
    let _ = cache;
}

#[tokio::test]
async fn test_dns_resolve_ip_address_directly() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // Resolving a literal IP address should return it directly
    let result = cache.resolve("127.0.0.1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_dns_resolve_ipv6_directly() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    let result = cache.resolve("::1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "::1");
}

#[tokio::test]
async fn test_dns_per_proxy_override() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // Per-proxy override should be used first
    let result = cache.resolve("example.com", Some("10.0.0.1"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.1");
}

#[tokio::test]
async fn test_dns_global_override() {
    let mut overrides = HashMap::new();
    overrides.insert("myhost.local".to_string(), "192.168.1.100".to_string());
    let cache = DnsCache::new(default_dns_config(300, overrides));

    let result = cache.resolve("myhost.local", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "192.168.1.100");
}

#[tokio::test]
async fn test_dns_per_proxy_override_takes_precedence_over_global() {
    let mut overrides = HashMap::new();
    overrides.insert("myhost.local".to_string(), "192.168.1.100".to_string());
    let cache = DnsCache::new(default_dns_config(300, overrides));

    // Per-proxy override should take precedence over global
    let result = cache.resolve("myhost.local", Some("10.0.0.5"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.5");
}

#[tokio::test]
async fn test_dns_invalid_override_ip() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // Invalid IP override should return an error
    let result = cache.resolve("example.com", Some("not-an-ip"), None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_resolve_localhost() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    // localhost should resolve to 127.0.0.1 or ::1
    assert!(addr.to_string() == "127.0.0.1" || addr.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_caching_returns_same_result() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // First resolution
    let result1 = cache.resolve("localhost", None, None).await.unwrap();
    // Second resolution should use cache
    let result2 = cache.resolve("localhost", None, None).await.unwrap();

    assert_eq!(result1, result2);
}

#[tokio::test]
async fn test_dns_warmup_does_not_panic() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    let hostnames = vec![
        ("localhost".to_string(), None, None),
        ("127.0.0.1".to_string(), None, None),
        ("nonexistent.invalid".to_string(), None, None), // Should warn but not panic
    ];

    cache.warmup(hostnames).await;
}

#[tokio::test]
async fn test_dns_warmup_with_overrides() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    let hostnames = vec![
        ("myhost.local".to_string(), Some("10.0.0.1".to_string()), Some(600)),
    ];

    cache.warmup(hostnames).await;

    // After warmup, the resolved IP should be cached
    let result = cache.resolve("myhost.local", Some("10.0.0.1"), None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_custom_ttl_per_proxy() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // Resolve with custom per-proxy TTL
    let result = cache.resolve("localhost", None, Some(60)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_resolve_nonexistent_domain() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    let result = cache.resolve("this-domain-absolutely-does-not-exist.invalid", None, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_cache_len_starts_empty() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));
    assert_eq!(cache.cache_len(), 0);
}

#[tokio::test]
async fn test_dns_warmup_populates_cache() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));
    assert_eq!(cache.cache_len(), 0);

    let hostnames = vec![
        ("localhost".to_string(), None, None),
        ("127.0.0.1".to_string(), None, None),
    ];
    cache.warmup(hostnames).await;

    // After warmup, cache should contain entries for resolved hostnames
    assert!(cache.cache_len() >= 1, "Warmup should populate at least one cache entry");
}

#[tokio::test]
async fn test_dns_ttl_expiration_causes_re_resolution() {
    // Use a very short TTL (1 second) and very short stale TTL (0 seconds)
    let cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    // First resolution populates cache
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for TTL + stale_ttl to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Second resolution should still succeed (re-resolves from DNS)
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(result1, result2, "Re-resolution should return same IP for localhost");
}

#[tokio::test]
async fn test_dns_concurrent_resolution_safety() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));
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
        assert!(result.is_ok(), "Concurrent resolution should not panic or error");
        results.push(result.unwrap());
    }

    // All should resolve to the same IP
    let first = results[0];
    for ip in &results {
        assert_eq!(*ip, first, "All concurrent resolutions should return the same IP");
    }
}

#[tokio::test]
async fn test_dns_per_proxy_override_bypasses_cache() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // Resolve with override — should NOT populate cache
    let result = cache.resolve("some-host.example.com", Some("10.0.0.1"), None).await.unwrap();
    assert_eq!(result.to_string(), "10.0.0.1");

    // Cache should be empty since overrides bypass caching
    assert_eq!(cache.cache_len(), 0, "Per-proxy override should bypass cache");
}

#[tokio::test]
async fn test_dns_cache_serves_from_cache_within_ttl() {
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

    // First call populates cache
    let _result1 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Second call should use cache (no way to directly verify but we can
    // confirm it returns immediately and gives same result)
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1, "Cache should still have exactly 1 entry");
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
}

// ============================================================================
// New tests for enhanced DNS features
// ============================================================================

#[tokio::test]
async fn test_dns_error_caching() {
    let cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 300,
        error_ttl_seconds: 5,
        ..DnsConfig::default()
    });

    // First resolution of non-existent domain should fail
    let result1 = cache.resolve("this-domain-absolutely-does-not-exist.invalid", None, None).await;
    assert!(result1.is_err(), "First resolution should fail");

    // Error should be cached
    assert!(cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"),
            "Error should be cached");

    // Second resolution should return cached error immediately
    let result2 = cache.resolve("this-domain-absolutely-does-not-exist.invalid", None, None).await;
    assert!(result2.is_err(), "Second resolution should also fail (cached error)");
}

#[tokio::test]
async fn test_dns_error_ttl_expiration() {
    let cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 300,
        error_ttl_seconds: 1,
        ..DnsConfig::default()
    });

    // Resolve a non-existent domain
    let _ = cache.resolve("this-domain-absolutely-does-not-exist.invalid", None, None).await;
    assert!(cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"));

    // Wait for error TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Cached error should have expired
    assert!(!cache.is_cached_error("this-domain-absolutely-does-not-exist.invalid"),
            "Cached error should expire after error_ttl");
}

#[tokio::test]
async fn test_dns_stale_while_revalidate() {
    // 1-second TTL with 10-second stale window
    let cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 1,
        stale_ttl_seconds: 10,
        ..DnsConfig::default()
    });

    // First resolution populates cache
    let result1 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for TTL to expire but stay within stale window
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Should return stale data (and trigger background refresh)
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(result1, result2, "Stale data should be returned during stale window");

    // Give background refresh time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Cache should have been refreshed
    assert_eq!(cache.cache_len(), 1, "Cache should still have the entry after refresh");
}

#[tokio::test]
async fn test_dns_valid_ttl_override() {
    let cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 300,
        valid_ttl_override: Some(1),
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    // Resolve populates cache
    let _result = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for the overridden TTL (1 second) to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Entry should have expired (valid_ttl_override=1s has passed, stale_ttl=0)
    // A fresh resolve should succeed via re-resolution
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert!(result2.to_string() == "127.0.0.1" || result2.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_order_default() {
    // Default order is CACHE,SRV,A,CNAME — A should resolve localhost
    let cache = DnsCache::new(default_dns_config(300, HashMap::new()));

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
    assert!(result.is_ok(), "Custom hosts file entry should resolve: {:?}", result);
    assert_eq!(result.unwrap().to_string(), "10.99.99.1");

    let result2 = cache.resolve("another-host.test", None, None).await;
    assert!(result2.is_ok(), "Second custom hosts entry should resolve");
    assert_eq!(result2.unwrap().to_string(), "10.99.99.2");
}

#[tokio::test]
async fn test_dns_config_default() {
    let config = DnsConfig::default();
    assert_eq!(config.default_ttl_seconds, 300);
    assert_eq!(config.stale_ttl_seconds, 3600);
    assert_eq!(config.error_ttl_seconds, 1);
    assert!(config.valid_ttl_override.is_none());
    assert!(config.resolver_addresses.is_none());
    assert!(config.hosts_file_path.is_none());
    assert!(config.dns_order.is_none());
    assert!(config.global_overrides.is_empty());
}

#[tokio::test]
async fn test_dns_stale_deadline_enforcement() {
    // Very short TTL and very short stale TTL
    let cache = DnsCache::new(DnsConfig {
        default_ttl_seconds: 1,
        stale_ttl_seconds: 1,
        ..DnsConfig::default()
    });

    // First resolution
    let result1 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for both TTL and stale_ttl to expire (1 + 1 = 2 seconds)
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Should re-resolve (not serve stale data since we're past stale_deadline)
    let result2 = cache.resolve("localhost", None, None).await.unwrap();
    assert_eq!(result1, result2, "Re-resolution should return same IP for localhost");
}
