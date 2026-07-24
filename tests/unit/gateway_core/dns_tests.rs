//! Tests for DNS cache and resolution module

use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use std::collections::HashMap;

/// Helper to create a default DnsConfig with custom overrides.
fn default_dns_config(overrides: HashMap<String, String>) -> DnsConfig {
    DnsConfig {
        global_overrides: overrides,
        ..DnsConfig::default()
    }
}

fn public_dns_config(overrides: HashMap<String, String>) -> DnsConfig {
    DnsConfig {
        global_overrides: overrides,
        backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
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
async fn test_dns_global_override_hostname_case_insensitive() {
    let mut overrides = HashMap::new();
    overrides.insert("Service.Local".to_string(), "192.0.2.10".to_string());
    let cache = DnsCache::new(default_dns_config(overrides));

    let result = cache.resolve("SERVICE.LOCAL", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "192.0.2.10");
    assert_eq!(
        cache.cache_len(),
        0,
        "Global overrides should bypass DNS cache insertion"
    );
}

#[tokio::test]
async fn test_dns_resolve_all_global_override_hostname_case_insensitive() {
    let mut overrides = HashMap::new();
    overrides.insert("Api.Internal".to_string(), "192.0.2.11".to_string());
    let cache = DnsCache::new(default_dns_config(overrides));

    let result = cache.resolve_all("api.internal", None, None).await;
    assert!(result.is_ok());
    assert_eq!(
        result
            .unwrap()
            .into_iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>(),
        vec!["192.0.2.11"]
    );
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
async fn test_dns_public_policy_denies_private_per_proxy_override() {
    let cache = DnsCache::new(public_dns_config(HashMap::new()));

    let result = cache
        .resolve("example.com", Some("169.254.169.254"), None)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_public_policy_denies_private_global_override() {
    let mut overrides = HashMap::new();
    overrides.insert("metadata.local".to_string(), "169.254.169.254".to_string());
    let cache = DnsCache::new(public_dns_config(overrides));

    let result = cache.resolve("metadata.local", None, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_public_policy_denies_case_insensitive_global_override() {
    let mut overrides = HashMap::new();
    overrides.insert("Metadata.Local".to_string(), "169.254.169.254".to_string());
    let cache = DnsCache::new(public_dns_config(overrides));

    let result = cache.resolve("METADATA.LOCAL", None, None).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("169.254.169.254"), "unexpected error: {err}");
    assert!(
        err.contains("denied by backend egress policy"),
        "unexpected error: {err}"
    );
}

/// A DnsConfig with the *production default* egress policy (mode `both` +
/// dangerous-range baseline on). Models a gateway with no `FERRUM_BACKEND_*`
/// env vars set.
fn default_egress_dns_config(overrides: HashMap<String, String>) -> DnsConfig {
    DnsConfig {
        global_overrides: overrides,
        backend_allow_ips: BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true)
            .expect("valid default policy"),
        ..DnsConfig::default()
    }
}

#[tokio::test]
async fn test_dns_default_policy_blocks_metadata_rebind() {
    // DNS-rebinding defense under the DEFAULT policy: a hostname whose answer
    // resolves (here via override) to the cloud-metadata address is rejected at
    // the cache-insertion path, so the denied IP is never cached or served —
    // even though the mode is `both`. Every fresh resolve is screened, which is
    // exactly what stops a public→private rebind.
    let mut overrides = HashMap::new();
    overrides.insert(
        "rebind.example.com".to_string(),
        "169.254.169.254".to_string(),
    );
    let cache = DnsCache::new(default_egress_dns_config(overrides));

    let result = cache.resolve("rebind.example.com", None, None).await;
    assert!(
        result.is_err(),
        "metadata answer must be rejected under the default policy"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("denied by backend egress policy"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn test_dns_default_policy_allows_loopback_and_rfc1918() {
    // The default must NOT break normal private backends (mesh/sidecar loopback,
    // internal RFC1918 services).
    let mut overrides = HashMap::new();
    overrides.insert("app.local".to_string(), "127.0.0.1".to_string());
    overrides.insert("svc.internal".to_string(), "10.0.0.5".to_string());
    let cache = DnsCache::new(default_egress_dns_config(overrides));

    assert!(cache.resolve("app.local", None, None).await.is_ok());
    assert!(cache.resolve("svc.internal", None, None).await.is_ok());
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
async fn test_dns_cache_key_hostname_case_insensitive_for_localhost() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result1 = cache.resolve("LOCALHOST", None, None).await.unwrap();
    let result2 = cache.resolve("localhost", None, None).await.unwrap();

    assert_eq!(result1, result2);
    assert_eq!(
        cache.cache_len(),
        1,
        "Case variants of one DNS hostname should share one cache entry"
    );
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
async fn test_dns_resolve_all_public_policy_denies_private_override() {
    let cache = DnsCache::new(public_dns_config(HashMap::new()));

    let result = cache
        .resolve_all("example.com", Some("192.168.1.1"), None)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_public_policy_denies_localhost() {
    let cache = DnsCache::new(public_dns_config(HashMap::new()));

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_resolve_all_public_policy_denies_localhost_and_does_not_cache() {
    let cache = DnsCache::new(public_dns_config(HashMap::new()));

    let result = cache.resolve_all("localhost", None, None).await;
    assert!(result.is_err());
    assert_eq!(
        cache.cache_len(),
        0,
        "Denied DNS answers must not be inserted into the shared cache"
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

// ============================================================================
// Cache eviction tests
// ============================================================================

#[tokio::test]
async fn test_evict_expired_removes_stale_entries() {
    let config = DnsConfig {
        // Very short TTL override so entries expire quickly
        ttl_override_seconds: Some(1),
        // Very short stale TTL so entries become evictable
        stale_ttl_seconds: 1,
        min_ttl_seconds: 1,
        ..DnsConfig::default()
    };
    let cache = DnsCache::new(config);

    // Populate cache with an IP override (direct IP bypass, creates cache entry)
    let _ = cache.resolve("10.0.0.1", None, None).await;
    let _ = cache.resolve("10.0.0.2", None, None).await;
    assert!(cache.cache_len() >= 2);

    // Wait for entries to expire past stale deadline
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let before = cache.cache_len();
    cache.evict_expired();

    assert!(
        cache.cache_len() < before,
        "evict_expired should reduce cache size from {} but got {}",
        before,
        cache.cache_len()
    );
}

#[tokio::test]
async fn test_evict_expired_on_empty_cache_is_noop() {
    let config = DnsConfig::default();
    let cache = DnsCache::new(config);

    assert_eq!(cache.cache_len(), 0);
    cache.evict_expired();
    assert_eq!(cache.cache_len(), 0);
}

#[tokio::test]
async fn test_max_cache_size_eviction() {
    let config = DnsConfig {
        max_cache_size: 5,
        ..DnsConfig::default()
    };
    let cache = DnsCache::new(config);

    // Fill cache with IP addresses (these are direct IP parses, not DNS lookups)
    for i in 0..10 {
        let ip = format!("10.0.0.{}", i);
        let _ = cache.resolve(&ip, None, None).await;
    }

    // After eviction, cache should be at or below max_cache_size
    cache.evict_expired();
    assert!(
        cache.cache_len() <= 5,
        "Cache should be bounded by max_cache_size, got {}",
        cache.cache_len()
    );
}

// ============================================================================
// SRV resolution tests
// ============================================================================

#[tokio::test]
async fn test_srv_resolution_nonexistent_service() {
    let config = DnsConfig::default();
    let cache = DnsCache::new(config);

    // Use .invalid TLD (RFC 6761 §6.4) — guaranteed to never resolve,
    // unlike .local which can trigger mDNS in some environments.
    let result = cache.resolve_srv("_nonexistent._tcp.test.invalid").await;
    assert!(
        result.is_err(),
        "SRV resolution of nonexistent service should fail"
    );
}

// ============================================================================
// Per-proxy TTL override tests
// ============================================================================

#[tokio::test]
async fn test_per_proxy_ttl_override_does_not_affect_resolved_address() {
    // Per-proxy TTL override is a freshness parameter — it must not change the
    // resolved IP, only when this caller treats the shared entry as stale.
    let config = DnsConfig {
        ttl_override_seconds: Some(300),
        min_ttl_seconds: 1,
        ..DnsConfig::default()
    };
    let cache = DnsCache::new(config);

    let result = cache.resolve("127.0.0.1", None, Some(1)).await;
    assert!(result.is_ok());

    let result2 = cache.resolve("127.0.0.1", None, Some(1)).await;
    assert!(result2.is_ok());
    assert_eq!(result.unwrap(), result2.unwrap());
}

// ============================================================================
// Per-proxy TTL isolation for shared hostnames (#2415)
// ============================================================================

#[tokio::test]
async fn test_shared_hostname_ttl_isolation_short_then_long() {
    // 5s then 600s insertion order: short consumer must expire independently.
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ttl_override_seconds: None,
        ..DnsConfig::default()
    });
    let metrics = ferrum_edge::runtime_metrics::global_ref();
    use std::sync::atomic::Ordering;

    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();
    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();

    let hits_before = metrics.dns_cache_hits.load(Ordering::Relaxed);
    let misses_before = metrics.dns_cache_misses.load(Ordering::Relaxed);

    // Still within 5s — both should hit.
    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();
    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();
    assert!(
        metrics.dns_cache_hits.load(Ordering::Relaxed) >= hits_before + 2,
        "both consumers must hit while within the short TTL window"
    );
    let _ = misses_before;

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    let misses_mid = metrics.dns_cache_misses.load(Ordering::Relaxed);

    // Short TTL is expired (stale_ttl=0) → miss / re-resolve.
    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();
    assert!(
        metrics.dns_cache_misses.load(Ordering::Relaxed) > misses_mid,
        "5s consumer must re-resolve after its TTL elapses"
    );

    // Long TTL still fresh against the shared resolved_at (possibly refreshed
    // by the short consumer's re-resolve above).
    let hits_before_long = metrics.dns_cache_hits.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();
    assert!(
        metrics.dns_cache_hits.load(Ordering::Relaxed) > hits_before_long,
        "600s consumer must hit the shared record after the short consumer refreshed"
    );
}

#[tokio::test]
async fn test_shared_hostname_ttl_isolation_long_then_short() {
    // 600s then 5s insertion order must behave the same as the reverse order.
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ttl_override_seconds: None,
        ..DnsConfig::default()
    });
    let metrics = ferrum_edge::runtime_metrics::global_ref();
    use std::sync::atomic::Ordering;

    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();
    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    let misses_before = metrics.dns_cache_misses.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();
    assert!(
        metrics.dns_cache_misses.load(Ordering::Relaxed) > misses_before,
        "5s consumer must re-resolve even when a 600s consumer populated the entry first"
    );

    let hits_before = metrics.dns_cache_hits.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();
    assert!(
        metrics.dns_cache_hits.load(Ordering::Relaxed) > hits_before,
        "600s consumer must still hit after the short consumer refreshed"
    );
}

#[tokio::test]
async fn test_warmup_order_does_not_select_winning_ttl() {
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });
    let metrics = ferrum_edge::runtime_metrics::global_ref();
    use std::sync::atomic::Ordering;

    // Warm with long TTL first (historical first-writer-wins failure mode).
    cache
        .warmup(vec![
            ("127.0.0.1".to_string(), None, Some(600)),
            ("127.0.0.1".to_string(), None, Some(5)),
        ])
        .await;

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    let misses_before = metrics.dns_cache_misses.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();
    assert!(
        metrics.dns_cache_misses.load(Ordering::Relaxed) > misses_before,
        "warmup with 600s first must not pin a short-TTL consumer to a long freshness window"
    );
}

#[tokio::test]
async fn test_reload_reorder_warmup_preserves_per_caller_ttl() {
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });
    let metrics = ferrum_edge::runtime_metrics::global_ref();
    use std::sync::atomic::Ordering;

    // Simulate reload reordering: short TTL listed first on the second warmup.
    cache
        .warmup(vec![
            ("127.0.0.1".to_string(), None, Some(600)),
            ("127.0.0.1".to_string(), None, Some(5)),
        ])
        .await;
    cache
        .warmup(vec![
            ("127.0.0.1".to_string(), None, Some(5)),
            ("127.0.0.1".to_string(), None, Some(600)),
        ])
        .await;

    tokio::time::sleep(std::time::Duration::from_secs(6)).await;

    let misses_before = metrics.dns_cache_misses.load(Ordering::Relaxed);
    let hits_before = metrics.dns_cache_hits.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, Some(5)).await.unwrap();
    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();
    assert!(
        metrics.dns_cache_misses.load(Ordering::Relaxed) > misses_before,
        "short TTL must miss after reload reorder"
    );
    assert!(
        metrics.dns_cache_hits.load(Ordering::Relaxed) > hits_before,
        "long TTL must still hit after reload reorder"
    );
}

#[tokio::test]
async fn test_global_native_precedence_with_shared_record() {
    // Per-proxy > global > native, evaluated per caller against shared data.
    let cache = DnsCache::new(DnsConfig {
        ttl_override_seconds: Some(3600),
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });
    let metrics = ferrum_edge::runtime_metrics::global_ref();
    use std::sync::atomic::Ordering;

    // Populate via a caller with no per-proxy TTL (uses global 3600).
    let _ = cache.resolve("127.0.0.1", None, None).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Caller with per-proxy TTL 1 must be expired despite global 3600 on the
    // original writer / shared entry.
    let misses_before = metrics.dns_cache_misses.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, Some(1)).await.unwrap();
    assert!(
        metrics.dns_cache_misses.load(Ordering::Relaxed) > misses_before,
        "per-proxy TTL must win over the global override for that caller"
    );

    // Caller with no per-proxy TTL still uses global 3600 → hit.
    let hits_before = metrics.dns_cache_hits.load(Ordering::Relaxed);
    let _ = cache.resolve("127.0.0.1", None, None).await.unwrap();
    assert!(
        metrics.dns_cache_hits.load(Ordering::Relaxed) > hits_before,
        "caller without per-proxy TTL must keep global/native freshness"
    );
}

#[tokio::test]
async fn test_concurrent_stale_refresh_dedup_with_divergent_ttls() {
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 30,
        max_concurrent_refreshes: 8,
        ..DnsConfig::default()
    });

    let _ = cache.resolve("127.0.0.1", None, Some(1)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Many concurrent short-TTL callers in the stale window must single-flight.
    let mut handles = Vec::new();
    for _ in 0..32 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            cache.resolve("127.0.0.1", None, Some(1)).await
        }));
    }
    for handle in handles {
        assert!(handle.await.unwrap().is_ok());
    }

    // Long-TTL callers hitting the same hostname must not create a second entry.
    let _ = cache.resolve("127.0.0.1", None, Some(600)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);
}


// ============================================================================
// Concurrent refresh limiter tests
// ============================================================================

#[tokio::test]
async fn test_dns_max_concurrent_refreshes_default() {
    let config = DnsConfig::default();
    assert_eq!(
        config.max_concurrent_refreshes, 64,
        "Default max_concurrent_refreshes should be 64"
    );
}

#[tokio::test]
async fn test_dns_stale_refresh_still_works_with_semaphore() {
    // Verify that the semaphore does not block normal stale-while-revalidate
    // refreshes — stale entries should still be served and refreshed.
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 10,
        max_concurrent_refreshes: 2,
        ..DnsConfig::default()
    });

    // Populate cache with 1s per-proxy TTL
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for TTL to expire but stay within stale window
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Should still return stale data (background refresh triggered, semaphore available)
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(
        result1, result2,
        "Stale data should be returned with semaphore-limited refresh"
    );

    // Give refresh time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(cache.cache_len(), 1);
}

#[tokio::test]
async fn test_dns_concurrent_refresh_limit_prevents_unbounded_tasks() {
    // Verify that the semaphore limits concurrent background refresh tasks.
    //
    // This test uses IP-literal entries which resolve instantly in do_resolve()
    // (parsed before hitting the resolver). Because refresh completes so quickly,
    // this test cannot directly *observe* the semaphore blocking concurrent tasks.
    // It instead verifies the end-to-end contract: all stale entries are still
    // served, the cache is not corrupted, and no panics occur under load.
    //
    // A stronger behavioral test would require injecting a mock/slow resolver
    // into DnsCache (the resolver is private and constructed internally), which
    // is not currently supported. The semaphore bound is verified structurally:
    //   - DnsCache::new() creates Semaphore::new(max_concurrent_refreshes.max(1))
    //   - resolve()/resolve_all() call try_acquire_owned() before spawning
    //   - On Err (all permits taken), the refresh is skipped and the dedup entry
    //     is removed so a future request can retry
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 60,
        max_concurrent_refreshes: 2, // Only 2 concurrent refreshes allowed
        ..DnsConfig::default()
    });

    // Populate cache with several IP-based entries (these resolve instantly)
    for i in 1..=10 {
        let ip = format!("10.0.0.{}", i);
        let _ = cache.resolve(&ip, None, Some(1)).await;
    }
    assert!(cache.cache_len() >= 10);

    // Wait for TTL to expire (entries become stale)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Hit all 10 stale entries — only max_concurrent_refreshes tasks should run
    // concurrently, the rest should be skipped (and still serve stale data)
    for i in 1..=10 {
        let ip = format!("10.0.0.{}", i);
        let result = cache.resolve(&ip, None, Some(1)).await;
        assert!(
            result.is_ok(),
            "Stale entries should still be served even when concurrency limit is hit"
        );
    }

    // Give refreshes time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // All entries should still be in the cache
    assert!(
        cache.cache_len() >= 10,
        "Cache entries should persist after refresh"
    );
}

#[tokio::test]
async fn test_dns_concurrent_stale_refresh_with_real_dns_hostnames() {
    // Use hostnames that require actual DNS resolution (not IP literals) to
    // add realistic latency to the refresh path. With max_concurrent_refreshes=1,
    // only one background refresh task can run at a time — excess requests are
    // skipped and stale data is served. This tests the contract under more
    // realistic conditions where refresh tasks hold permits for non-trivial time.
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 60,
        max_concurrent_refreshes: 1, // Strictest possible limit
        ..DnsConfig::default()
    });

    // Populate cache with localhost — resolves via hosts file / resolver
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Also populate with an IP (different entry, instant resolution)
    let ip_result = cache.resolve("127.0.0.1", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 2);

    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Hit both stale entries concurrently — with semaphore=1, at most one
    // refresh task runs. The other is skipped and stale data is served.
    let cache_a = cache.clone();
    let cache_b = cache.clone();
    let (r1, r2) = tokio::join!(
        cache_a.resolve("localhost", None, Some(1)),
        cache_b.resolve("127.0.0.1", None, Some(1)),
    );
    assert_eq!(r1.unwrap(), result1, "Stale localhost should be served");
    assert_eq!(r2.unwrap(), ip_result, "Stale IP should be served");

    // Give the single permitted refresh time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Both entries should still exist in cache
    assert_eq!(cache.cache_len(), 2);
}

#[tokio::test]
async fn test_dns_refresh_semaphore_min_clamped_to_one() {
    // Verify that max_concurrent_refreshes=0 is clamped to 1 (the .max(1) in
    // DnsCache::new), so at least one refresh can always proceed.
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 10,
        max_concurrent_refreshes: 0, // Clamped to 1 inside DnsCache::new
        ..DnsConfig::default()
    });

    // Populate and expire
    let result1 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Stale resolve should still work — the one permit allows the refresh
    let result2 = cache.resolve("localhost", None, Some(1)).await.unwrap();
    assert_eq!(result1, result2, "Stale data should be served");

    // Refresh should complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(cache.cache_len(), 1);
}

#[tokio::test]
async fn test_dns_resolve_all_respects_refresh_semaphore() {
    // Verify that resolve_all also respects the semaphore
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 10,
        max_concurrent_refreshes: 2,
        ..DnsConfig::default()
    });

    // Populate cache
    let result1 = cache.resolve_all("localhost", None, Some(1)).await.unwrap();
    assert!(!result1.is_empty());

    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // resolve_all should serve stale data and trigger bounded refresh
    let result2 = cache.resolve_all("localhost", None, Some(1)).await.unwrap();
    assert_eq!(result1, result2);

    // Give refresh time to complete
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(cache.cache_len(), 1);
}
