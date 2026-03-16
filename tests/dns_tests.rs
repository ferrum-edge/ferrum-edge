//! Tests for DNS cache and resolution module

use ferrum_gateway::dns::DnsCache;
use std::collections::HashMap;

#[tokio::test]
async fn test_dns_cache_creation() {
    let cache = DnsCache::new(300, HashMap::new());
    // Should be able to create a cache
    let _ = cache;
}

#[tokio::test]
async fn test_dns_resolve_ip_address_directly() {
    let cache = DnsCache::new(300, HashMap::new());

    // Resolving a literal IP address should return it directly
    let result = cache.resolve("127.0.0.1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "127.0.0.1");
}

#[tokio::test]
async fn test_dns_resolve_ipv6_directly() {
    let cache = DnsCache::new(300, HashMap::new());

    let result = cache.resolve("::1", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "::1");
}

#[tokio::test]
async fn test_dns_per_proxy_override() {
    let cache = DnsCache::new(300, HashMap::new());

    // Per-proxy override should be used first
    let result = cache.resolve("example.com", Some("10.0.0.1"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.1");
}

#[tokio::test]
async fn test_dns_global_override() {
    let mut overrides = HashMap::new();
    overrides.insert("myhost.local".to_string(), "192.168.1.100".to_string());
    let cache = DnsCache::new(300, overrides);

    let result = cache.resolve("myhost.local", None, None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "192.168.1.100");
}

#[tokio::test]
async fn test_dns_per_proxy_override_takes_precedence_over_global() {
    let mut overrides = HashMap::new();
    overrides.insert("myhost.local".to_string(), "192.168.1.100".to_string());
    let cache = DnsCache::new(300, overrides);

    // Per-proxy override should take precedence over global
    let result = cache.resolve("myhost.local", Some("10.0.0.5"), None).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().to_string(), "10.0.0.5");
}

#[tokio::test]
async fn test_dns_invalid_override_ip() {
    let cache = DnsCache::new(300, HashMap::new());

    // Invalid IP override should return an error
    let result = cache.resolve("example.com", Some("not-an-ip"), None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_dns_resolve_localhost() {
    let cache = DnsCache::new(300, HashMap::new());

    let result = cache.resolve("localhost", None, None).await;
    assert!(result.is_ok());
    let addr = result.unwrap();
    // localhost should resolve to 127.0.0.1 or ::1
    assert!(addr.to_string() == "127.0.0.1" || addr.to_string() == "::1");
}

#[tokio::test]
async fn test_dns_caching_returns_same_result() {
    let cache = DnsCache::new(300, HashMap::new());

    // First resolution
    let result1 = cache.resolve("localhost", None, None).await.unwrap();
    // Second resolution should use cache
    let result2 = cache.resolve("localhost", None, None).await.unwrap();

    assert_eq!(result1, result2);
}

#[tokio::test]
async fn test_dns_warmup_does_not_panic() {
    let cache = DnsCache::new(300, HashMap::new());

    let hostnames = vec![
        ("localhost".to_string(), None, None),
        ("127.0.0.1".to_string(), None, None),
        ("nonexistent.invalid".to_string(), None, None), // Should warn but not panic
    ];

    cache.warmup(hostnames).await;
}

#[tokio::test]
async fn test_dns_warmup_with_overrides() {
    let cache = DnsCache::new(300, HashMap::new());

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
    let cache = DnsCache::new(300, HashMap::new());

    // Resolve with custom per-proxy TTL
    let result = cache.resolve("localhost", None, Some(60)).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dns_resolve_nonexistent_domain() {
    let cache = DnsCache::new(300, HashMap::new());

    let result = cache.resolve("this-domain-absolutely-does-not-exist.invalid", None, None).await;
    assert!(result.is_err());
}
