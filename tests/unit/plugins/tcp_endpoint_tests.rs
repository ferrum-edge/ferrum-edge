//! Behaviour tests for `resolve_tcp_endpoint`.
//!
//! Mirrors `udp_endpoint_tests.rs`. Locks in the policy that when a
//! `DnsCache` is provided, errors from `DnsCache::resolve` are
//! authoritative and the helper does NOT fall back to the OS resolver.

use std::collections::HashMap;

use ferrum_edge::config::BackendAllowIps;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::utils::resolve_tcp_endpoint;

fn cache_with_override_and_policy(host: &str, ip: &str, policy: BackendAllowIps) -> DnsCache {
    let mut overrides = HashMap::new();
    overrides.insert(host.to_string(), ip.to_string());
    DnsCache::new(DnsConfig {
        global_overrides: overrides,
        backend_allow_ips: policy,
        ..DnsConfig::default()
    })
}

#[tokio::test]
async fn cache_ip_policy_denial_propagates_no_os_fallback() {
    let cache = cache_with_override_and_policy("localhost", "127.0.0.1", BackendAllowIps::Public);

    let result = resolve_tcp_endpoint("localhost", 9000, Some(&cache), "tcp_endpoint_test").await;

    let err = result.expect_err("cache IP-policy denial must propagate as Err");
    assert!(
        err.contains("tcp_endpoint_test"),
        "error must include plugin label, got: {err}"
    );
    assert!(
        !err.contains("system DNS"),
        "error must not advertise OS-DNS fallback, got: {err}"
    );
}

#[tokio::test]
async fn cache_override_parse_failure_propagates_no_os_fallback() {
    let cache = cache_with_override_and_policy("localhost", "not-an-ip", BackendAllowIps::Both);

    let result = resolve_tcp_endpoint("localhost", 9000, Some(&cache), "tcp_endpoint_test").await;

    assert!(
        result.is_err(),
        "malformed override must surface as cache error, not be papered over by OS DNS"
    );
}

#[tokio::test]
async fn cache_success_returns_resolved_socket_addr() {
    let cache = cache_with_override_and_policy("localhost", "127.0.0.1", BackendAllowIps::Both);

    let addr = resolve_tcp_endpoint("localhost", 9000, Some(&cache), "tcp_endpoint_test")
        .await
        .expect("override should resolve cleanly under permissive policy");

    assert_eq!(addr.port(), 9000);
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
}
