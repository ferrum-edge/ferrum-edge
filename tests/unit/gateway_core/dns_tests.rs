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
    assert_eq!(cache.cache_len(), 0, "IP literals must not be cached");
}

#[tokio::test]
async fn test_dns_resolve_ipv6_directly() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    let result = cache.resolve("::1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "::1");
    assert_eq!(cache.cache_len(), 0, "IPv6 literals must not be cached");
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
async fn test_dns_warmup_skips_empty_upstream_placeholders() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    cache
        .warmup(vec![
            (String::new(), None, None),
            ("   ".to_string(), None, None),
        ])
        .await;

    assert_eq!(
        cache.cache_len(),
        0,
        "empty upstream-backed proxy hosts must not become search-domain lookups"
    );
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

    // After warmup, only the real hostname is cached — IP literals are skipped.
    assert_eq!(
        cache.cache_len(),
        1,
        "Warmup should populate the hostname and skip the IP literal"
    );
    assert!(cache.is_cached("localhost"));
    assert!(
        !cache.is_cached("127.0.0.1"),
        "IP literals must not occupy a success-cache row"
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

/// Issue #7204: a hosts file that fails part-way through reading must not
/// install the partial table it produced. The valid first line would resolve
/// if the truncated table were applied.
#[tokio::test]
async fn test_dns_custom_hosts_file_read_error_is_not_applied() {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("broken_hosts");
    {
        let mut f = std::fs::File::create(&hosts_path).unwrap();
        writeln!(f, "10.99.98.1  partial-hosts-entry.test").unwrap();
        // Invalid UTF-8 makes the line reader fail after the first entry.
        f.write_all(b"10.99.98.2  \xff\xfe-broken.test\n").unwrap();
    }

    let cache = DnsCache::new(DnsConfig {
        hosts_file_path: Some(hosts_path.to_str().unwrap().to_string()),
        ..DnsConfig::default()
    });

    // Without the partial table the name falls through to real resolution,
    // which cannot answer a `.test` name with this address. Bound the wait so
    // an unreachable nameserver cannot stall the test; a timeout also proves
    // the partial entry was not served.
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        cache.resolve("partial-hosts-entry.test", None, None),
    )
    .await;
    if let Ok(Ok(addr)) = outcome {
        assert_ne!(
            addr.to_string(),
            "10.99.98.1",
            "a hosts file that failed to read must not be applied partially"
        );
    }
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

    // Populate cache with a real hostname (IP literals are not cached).
    let _ = cache.resolve("localhost", None, None).await;
    assert_eq!(cache.cache_len(), 1);

    // Wait for entries to expire past stale deadline
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    cache.evict_expired();

    assert_eq!(
        cache.cache_len(),
        0,
        "evict_expired should drop the expired localhost row"
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

    // IP literals must not occupy cache rows or count toward capacity.
    for i in 0..10 {
        let ip = format!("10.0.0.{}", i);
        let _ = cache.resolve(&ip, None, None).await;
    }

    cache.evict_expired();
    assert_eq!(
        cache.cache_len(),
        0,
        "IP literals must not create success-cache rows, got {}",
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

#[test]
fn resolve_srv_discards_rfc2782_root_target_and_port_zero() {
    use ferrum_edge::_test_support::try_srv_answer_for_test;

    assert!(
        try_srv_answer_for_test(".", 8080, 1, 10).is_none(),
        "RFC 2782 root target '.' must be discarded"
    );
    assert!(
        try_srv_answer_for_test("", 8080, 1, 10).is_none(),
        "empty name after stripping the root label is the same unavailability signal"
    );
    assert!(
        try_srv_answer_for_test("primary.example.com.", 0, 1, 10).is_none(),
        "port 0 is the RFC 2782 unavailability / non-dialable signal"
    );
    assert!(
        try_srv_answer_for_test("..", 8080, 1, 10).is_none(),
        "dotted-only names are the DNS root after stripping trailing labels"
    );
    assert!(
        try_srv_answer_for_test("...", 443, 1, 0).is_none(),
        "dotted-only names at priority 0 must still be discarded"
    );

    let answer = try_srv_answer_for_test("primary.example.com.", 8080, 7, 10)
        .expect("dialable SRV RR must be admitted");
    assert_eq!(answer.host, "primary.example.com");
    assert_eq!(answer.port, 8080);
    assert_eq!(answer.weight, 7);
    assert_eq!(answer.priority, 10);

    let mixed = try_srv_answer_for_test("Primary.Example.COM.", 65535, 65535, 0)
        .expect("mixed-case dialable SRV RR must be admitted");
    assert_eq!(mixed.host, "primary.example.com");
    assert_eq!(mixed.port, 65535);
    assert_eq!(mixed.weight, 65535);
    assert_eq!(mixed.priority, 0);
}

/// The ADDRESS-ONLY SRV mode (`FERRUM_DNS_ORDER` containing `SRV`) and
/// the DNS-SD service-availability path (`resolve_srv`) read the same RR type
/// with deliberately different rules (issue #4291). This pins the distinction
/// so neither silently inherits the other's contradictory behavior.
#[test]
fn address_only_srv_mode_ignores_port_but_honors_root_target_and_priority() {
    const DNS_SOURCE: &str = include_str!("../../../src/dns/mod.rs");

    let arm_start = DNS_SOURCE
        .find("CachedRecordType::Srv =>")
        .expect("the address-only SRV resolver arm must exist");
    let arm_end = arm_start
        + DNS_SOURCE[arm_start..]
            .find("CachedRecordType::Cname")
            .expect("the SRV arm must be followed by the CNAME arm");
    let arm = &DNS_SOURCE[arm_start..arm_end];

    assert!(
        !arm.contains("srv.port"),
        "address-only SRV resolution must never read the RR's port: it dials the proxy's \
         own configured backend port, so a port-0 RR still carries a usable address"
    );
    assert!(
        !arm.contains("admit_registry_port"),
        "registry-port admission belongs to the DNS-SD service-availability path only"
    );
    assert!(
        arm.contains("is_rfc2782_root_target"),
        "the RFC 2782 root target IS an availability signal and must be honored here too"
    );
    assert!(
        arm.contains("srv.priority"),
        "answers must be walked in ascending RFC 2782 priority so the lowest reachable \
         tier wins and the chosen address is independent of answer order"
    );

    // `resolve_srv` — the service-availability path — does the opposite for port.
    assert!(
        ferrum_edge::_test_support::try_srv_answer_for_test("primary.example.com.", 0, 1, 10)
            .is_none(),
        "DNS-SD admission must still reject port 0"
    );

    const DNS_DOC: &str = include_str!("../../../docs/dns_resolver.md");
    assert!(
        DNS_DOC.contains("Address-only SRV mode"),
        "the two modes' differing port/priority semantics must stay documented"
    );
}

// ============================================================================
// Per-proxy TTL override tests
// ============================================================================

#[tokio::test]
async fn test_per_proxy_ttl_override_does_not_affect_resolution() {
    // Per-proxy TTL override is an internal caching parameter — it should not
    // change the resolved IP, only how long the entry lives in cache.
    let config = DnsConfig {
        ttl_override_seconds: Some(300),
        ..DnsConfig::default()
    };
    let cache = DnsCache::new(config);

    // Resolve with a per-proxy TTL override of 1s. Literals are not cached, so
    // the override cannot change the returned address.
    let result = cache.resolve("127.0.0.1", None, Some(1)).await;
    assert!(result.is_ok());

    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    let result2 = cache.resolve("127.0.0.1", None, Some(1)).await;
    assert!(result2.is_ok());
    assert_eq!(result.unwrap(), result2.unwrap());
    assert_eq!(
        cache.cache_len(),
        0,
        "IP literals must not occupy a success-cache row"
    );
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
    // IP literals are not cached (issue #4293), so this test confirms they
    // still resolve under load without occupying rows or spawning refresh
    // tasks. The semaphore bound for real hostnames is covered by the
    // localhost stale-refresh tests below.
    let cache = DnsCache::new(DnsConfig {
        min_ttl_seconds: 1,
        stale_ttl_seconds: 60,
        max_concurrent_refreshes: 2, // Only 2 concurrent refreshes allowed
        ..DnsConfig::default()
    });

    // IP literals resolve without occupying cache rows, so they cannot
    // spawn stale-refresh tasks or overflow the semaphore.
    for i in 1..=10 {
        let ip = format!("10.0.0.{}", i);
        let _ = cache.resolve(&ip, None, Some(1)).await;
    }
    assert_eq!(
        cache.cache_len(),
        0,
        "IP literals must not occupy success-cache rows"
    );

    for i in 1..=10 {
        let ip = format!("10.0.0.{}", i);
        let result = cache.resolve(&ip, None, Some(1)).await;
        assert!(
            result.is_ok(),
            "IP literals must still resolve after repeated lookups"
        );
    }

    assert_eq!(cache.cache_len(), 0);
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

    // An IP literal still resolves but must not occupy a second cache row.
    let ip_result = cache.resolve("127.0.0.1", None, Some(1)).await.unwrap();
    assert_eq!(cache.cache_len(), 1);

    // Wait for TTL to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Hit the stale hostname and the literal concurrently. The literal is not
    // cached, so it cannot consume a refresh permit.
    let cache_a = cache.clone();
    let cache_b = cache.clone();
    let (r1, r2) = tokio::join!(
        cache_a.resolve("localhost", None, Some(1)),
        cache_b.resolve("127.0.0.1", None, Some(1)),
    );
    assert_eq!(r1.unwrap(), result1, "Stale localhost should be served");
    assert_eq!(r2.unwrap(), ip_result, "IP literal should still resolve");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    assert_eq!(cache.cache_len(), 1);
    assert!(cache.is_cached("localhost"));
    assert!(!cache.is_cached("127.0.0.1"));
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

// ============================================================================
// Per-proxy TTL isolation on shared hostnames (issue #2415)
// ============================================================================

#[tokio::test]
async fn test_shared_hostname_ttl_isolation_both_insertion_orders() {
    // Public-API coverage: two consumers sharing localhost at 1s/600s must
    // each honor their own freshness window regardless of who resolved first.
    for (first, second) in [(1u64, 600u64), (600u64, 1u64)] {
        let cache = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            ttl_override_seconds: None,
            ..DnsConfig::default()
        });

        cache
            .resolve("localhost", None, Some(first))
            .await
            .expect("first consumer");
        cache
            .resolve("localhost", None, Some(second))
            .await
            .expect("second consumer");
        assert_eq!(cache.cache_len(), 1, "shared hostname stays one cache row");

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let long = cache
            .resolve("localhost", None, Some(600))
            .await
            .expect("long-TTL consumer");
        assert!(long.is_ipv4() || long.is_ipv6());

        let short = cache
            .resolve("localhost", None, Some(1))
            .await
            .expect("short-TTL consumer");
        assert_eq!(long, short);
        assert_eq!(cache.cache_len(), 1);
    }
}

#[tokio::test]
async fn test_warmup_reordering_shared_hostname_ttl_isolation() {
    for order in [
        vec![
            ("localhost".to_string(), None, Some(1u64)),
            ("localhost".to_string(), None, Some(600u64)),
        ],
        vec![
            ("localhost".to_string(), None, Some(600u64)),
            ("localhost".to_string(), None, Some(1u64)),
        ],
    ] {
        let cache = DnsCache::new(DnsConfig {
            min_ttl_seconds: 1,
            stale_ttl_seconds: 0,
            ..DnsConfig::default()
        });
        cache.warmup(order).await;
        assert_eq!(cache.cache_len(), 1);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        assert!(
            cache.resolve("localhost", None, Some(600)).await.is_ok(),
            "600s consumer stays fresh after either warmup order"
        );
        assert!(
            cache.resolve("localhost", None, Some(1)).await.is_ok(),
            "1s consumer re-resolves after either warmup order"
        );
    }
}

#[tokio::test]
async fn test_per_proxy_vs_global_ttl_precedence_on_shared_hostname() {
    let cache = DnsCache::new(DnsConfig {
        ttl_override_seconds: Some(3600),
        min_ttl_seconds: 1,
        stale_ttl_seconds: 0,
        ..DnsConfig::default()
    });

    cache
        .resolve("localhost", None, Some(1))
        .await
        .expect("per-proxy consumer");
    cache
        .resolve("localhost", None, None)
        .await
        .expect("global-policy consumer");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    assert!(
        cache.resolve("localhost", None, None).await.is_ok(),
        "global 3600s policy must still be fresh"
    );
    assert!(
        cache.resolve("localhost", None, Some(1)).await.is_ok(),
        "per-proxy 1s policy must re-resolve after expiry"
    );
}

// ============================================================================
// Reqwest DnsCacheResolver + per-proxy dns_override (issue #2414)
// ============================================================================

#[tokio::test]
async fn reqwest_resolver_dns_override_pins_load_balanced_target_hostnames() {
    use ferrum_edge::dns::DnsCacheResolver;
    use reqwest::dns::Resolve;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // Failure scenario from #2414: backend_host is a route template, selected
    // targets differ, and dns_override must still determine the dial IP for
    // every initial / retry hostname — not only the template host.
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    let override_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let resolver = DnsCacheResolver::with_dns_override(cache, Some(override_ip.to_string()));

    let base_host = "route-template.internal";
    let initial_target = "target-a.internal";
    let retry_target = "target-b.internal";
    assert_ne!(base_host, initial_target);
    assert_ne!(initial_target, retry_target);

    for host in [base_host, initial_target, retry_target] {
        let addrs: Vec<_> = resolver
            .resolve(host.parse().expect("valid dns name"))
            .await
            .expect("override resolve")
            .collect();
        assert_eq!(
            addrs,
            vec![SocketAddr::new(override_ip, 0)],
            "reqwest resolver must dial override for selected host {host}"
        );
    }
}

#[tokio::test]
async fn reqwest_resolver_dns_override_matches_direct_connector_resolve() {
    use ferrum_edge::dns::DnsCacheResolver;
    use reqwest::dns::Resolve;
    use std::net::SocketAddr;

    // Parity: direct connectors call DnsCache::resolve_candidates(host, Some(ovr), …);
    // the reqwest pool installs the same override on DnsCacheResolver.
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    let override_ip = "192.0.2.55";
    let host = "lb-target.internal";

    let direct = cache
        .resolve_candidates(host, Some(override_ip), None)
        .await
        .expect("direct resolve_candidates");
    let resolver =
        DnsCacheResolver::with_dns_override(cache.clone(), Some(override_ip.to_string()));
    let reqwest_addrs: Vec<_> = resolver
        .resolve(host.parse().expect("valid dns name"))
        .await
        .expect("reqwest resolver")
        .collect();

    assert_eq!(direct.len(), 1);
    let direct_ip = direct.first().expect("override answer");
    assert_eq!(
        reqwest_addrs,
        vec![SocketAddr::new(direct_ip, 0)],
        "reqwest dial destination must match direct-connector override resolution"
    );
    // Telemetry / backend_resolved_ip also uses DnsCache::resolve with the
    // override; that first address must agree with the dial set.
    let telemetry = cache
        .resolve(host, Some(override_ip), None)
        .await
        .expect("telemetry resolve");
    assert_eq!(telemetry, direct_ip);
}

#[tokio::test]
async fn reqwest_dns_override_dials_override_and_preserves_selected_host() {
    use ferrum_edge::dns::DnsCacheResolver;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind override listener");
    let port = listener.local_addr().expect("listener address").port();
    let accepted =
        tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .expect("reqwest dial timeout")
                .expect("accept reqwest dial");
            let mut request = vec![0u8; 4096];
            let read = stream.read(&mut request).await.expect("read request");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(
                request.lines().any(|line| line
                    .eq_ignore_ascii_case(&format!("host: selected-target.invalid:{port}"))),
                "the HTTP Host identity must remain the selected target: {request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write response");
        });

    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    let resolver = DnsCacheResolver::with_dns_override(cache, Some("127.0.0.1".to_string()));
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .dns_resolver(Arc::new(resolver))
        .build()
        .expect("build reqwest client");
    let response = client
        .get(format!("http://selected-target.invalid:{port}/"))
        .send()
        .await
        .expect("dial through dns_override");

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.expect("response body"), "ok");
    accepted.await.expect("override listener task");
}

#[tokio::test]
async fn reqwest_resolver_without_override_uses_cached_answers() {
    use ferrum_edge::dns::DnsCacheResolver;
    use reqwest::dns::Resolve;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    // Warm via a successful override resolve that does NOT populate the cache,
    // then resolve localhost without override to prove the no-override path
    // still hits the shared cache / system resolver.
    let resolver = DnsCacheResolver::new(cache);
    let addrs: Vec<_> = resolver
        .resolve("127.0.0.1".parse().expect("literal name"))
        .await
        .expect("literal resolve")
        .collect();
    assert_eq!(
        addrs,
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)]
    );
}

// ============================================================================
// Dial-time all-candidates resolution with a per-proxy dns_override
// (RFC 9298 CONNECT-UDP tunnels, and any other fresh-resolution dial path)
// ============================================================================

#[tokio::test]
async fn fresh_all_candidates_resolution_honors_the_per_proxy_dns_override() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));

    // Without the override this name has no answer at all, so a passing
    // assertion can only come from the override being honored — not from the
    // resolver happening to agree.
    let resolved = cache
        .resolve_all_fresh_with_override("pinned-backend.invalid", Some("127.0.0.53"))
        .await
        .expect("the per-proxy override must be honored on the fresh dial path");
    assert_eq!(
        resolved,
        vec!["127.0.0.53".parse::<std::net::IpAddr>().expect("literal")],
        "a dial-time lookup must reach the same address ordinary dispatch would"
    );
}

#[tokio::test]
async fn fresh_all_candidates_resolution_screens_a_denied_dns_override() {
    // Public-only egress policy: a loopback override is denied. The override
    // must NOT bypass the backend IP policy just because it skips the resolver.
    let cache = DnsCache::new(public_dns_config(HashMap::new()));

    let error = cache
        .resolve_all_fresh_with_override("pinned-backend.invalid", Some("127.0.0.53"))
        .await
        .expect_err("a denied override must fail the lookup, not become an unscreened dial");
    let error = error.to_string();
    assert!(
        !error.is_empty(),
        "the policy refusal must surface as an error"
    );
}

#[tokio::test]
async fn fresh_all_candidates_resolution_without_an_override_is_unchanged() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    let resolved = cache
        .resolve_all_fresh_with_override("127.0.0.1", None)
        .await
        .expect("literal resolve");
    assert_eq!(
        resolved,
        vec!["127.0.0.1".parse::<std::net::IpAddr>().expect("literal")]
    );
}

// ============================================================================
// IP literals must not invert DNS cache eviction (issue #4293)
// ============================================================================

#[tokio::test]
async fn ip_literals_are_not_cached_and_cannot_displace_short_ttl_hostname() {
    let cache = DnsCache::new(DnsConfig {
        max_cache_size: 4,
        min_ttl_seconds: 1,
        stale_ttl_seconds: 3600,
        ..DnsConfig::default()
    });

    cache
        .resolve("localhost", None, Some(30))
        .await
        .expect("short-TTL hostname");
    assert_eq!(cache.cache_len(), 1);
    assert!(cache.is_cached("localhost"));

    for i in 0..8u8 {
        let ip = format!("10.0.0.{i}");
        let addr = cache
            .resolve(&ip, None, None)
            .await
            .unwrap_or_else(|err| panic!("literal {ip} must resolve: {err}"));
        assert_eq!(addr.to_string(), ip);
        let v6 = format!("2001:db8::{i:x}");
        cache
            .resolve(&v6, None, None)
            .await
            .unwrap_or_else(|err| panic!("IPv6 literal {v6} must resolve: {err}"));
    }

    assert_eq!(
        cache.cache_len(),
        1,
        "literals must not occupy success-cache rows under capacity pressure"
    );
    cache.evict_expired();
    assert_eq!(cache.cache_len(), 1);
    assert!(
        cache.is_cached("localhost"),
        "short-TTL hostname must survive capacity pressure from IP literals"
    );
    assert!(!cache.is_cached("10.0.0.1"));
    assert!(!cache.is_cached("2001:db8::1"));
}

#[tokio::test]
async fn literal_warmup_publication_churn_does_not_evict_short_ttl_hostname() {
    let cache = DnsCache::new(DnsConfig {
        max_cache_size: 4,
        min_ttl_seconds: 1,
        stale_ttl_seconds: 3600,
        ..DnsConfig::default()
    });

    cache
        .resolve("localhost", None, Some(30))
        .await
        .expect("short-TTL hostname");

    for generation in 0..3u8 {
        let mut hosts = vec![("localhost".to_string(), None, Some(30u64))];
        for i in 0..8u8 {
            hosts.push((format!("10.{generation}.0.{i}"), None, None));
        }
        cache.warmup(hosts).await;
        assert_eq!(
            cache.cache_len(),
            1,
            "generation {generation}: literals must not occupy cache rows"
        );
        assert!(
            cache.is_cached("localhost"),
            "generation {generation}: short-TTL hostname must survive publication churn"
        );
    }

    cache.evict_expired();
    assert_eq!(cache.cache_len(), 1);
    assert!(cache.is_cached("localhost"));
    assert!(!cache.is_cached("10.0.0.1"));
    assert!(!cache.is_cached("10.2.0.7"));
}

#[tokio::test]
async fn dns_warmup_skips_ip_literals_without_policy_bypass() {
    let cache = DnsCache::new(public_dns_config(HashMap::new()));
    cache
        .warmup(vec![
            ("169.254.169.254".to_string(), None, None),
            ("10.0.0.1".to_string(), None, None),
            ("::1".to_string(), None, None),
        ])
        .await;
    assert_eq!(cache.cache_len(), 0);

    // Skipping warmup is not a policy bypass: request-time resolve still screens.
    let metadata = cache
        .resolve("169.254.169.254", None, None)
        .await
        .expect_err("metadata literal must be denied")
        .to_string();
    assert!(
        metadata.contains("denied by backend egress policy"),
        "unexpected error: {metadata}"
    );
    assert!(cache.resolve("10.0.0.1", None, None).await.is_err());
    assert!(cache.resolve("::1", None, None).await.is_err());
    assert_eq!(cache.cache_len(), 0);
}

#[tokio::test]
async fn per_proxy_override_still_wins_for_literal_hostname() {
    let cache = DnsCache::new(default_dns_config(HashMap::new()));
    let result = cache
        .resolve("10.0.0.1", Some("10.0.0.9"), None)
        .await
        .expect("override");
    assert_eq!(result.to_string(), "10.0.0.9");
    assert_eq!(cache.cache_len(), 0);
}

#[tokio::test]
async fn global_override_still_wins_for_literal_hostname() {
    let mut overrides = HashMap::new();
    overrides.insert("10.0.0.1".to_string(), "10.0.0.9".to_string());
    let cache = DnsCache::new(default_dns_config(overrides));
    let result = cache
        .resolve("10.0.0.1", None, None)
        .await
        .expect("global override");
    assert_eq!(result.to_string(), "10.0.0.9");
    assert_eq!(cache.cache_len(), 0);
}

#[tokio::test]
async fn public_policy_denies_literal_without_caching() {
    let cache = DnsCache::new(public_dns_config(HashMap::new()));
    let err = cache
        .resolve("169.254.169.254", None, None)
        .await
        .expect_err("metadata literal must be denied")
        .to_string();
    assert!(
        err.contains("denied by backend egress policy"),
        "unexpected error: {err}"
    );
    assert_eq!(cache.cache_len(), 0);
    assert!(!cache.is_cached("169.254.169.254"));
}

// ============================================================================
// Proactive background refresh hardening (issue #4270)
// ============================================================================

#[test]
fn proactive_refresh_and_eviction_intervals_use_missed_tick_delay() {
    let source = include_str!("../../../src/dns/mod.rs");
    let delay_hits = source.matches("MissedTickBehavior::Delay").count();
    assert!(
        delay_hits >= 3,
        "proactive refresh, independent eviction, and failed-retry must Delay missed ticks, found {delay_hits}"
    );
}
