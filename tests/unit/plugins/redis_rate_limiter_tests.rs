use ferrum_edge::_test_support::{RedisConfig, redis_config_url_with_ip};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn make_config(url: &str, tls: bool) -> RedisConfig {
    RedisConfig {
        url: url.to_string(),
        tls,
        key_prefix: "ferrum:test".to_string(),
        pool_size: 4,
        connect_timeout_seconds: 5,
        health_check_interval_seconds: 5,
        username: None,
        password: None,
    }
}

#[test]
fn test_hostname_uses_url_parser_and_preserves_credentials() {
    let config = make_config("redis://user:pass@redis:6379/15", false);
    assert_eq!(config.hostname().as_deref(), Some("redis"));
}

#[test]
fn test_url_with_resolved_ip_replaces_host_not_scheme() {
    let config = make_config("redis://redis:6379/0", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(url, "redis://127.0.0.1:6379/0");
}

#[test]
fn test_url_with_resolved_ip_preserves_credentials_and_path() {
    let config = make_config("redis://user:pass@redis:6379/15", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(url, "redis://user:pass@10.0.0.5:6379/15");
}

#[test]
fn test_url_with_resolved_ip_formats_ipv6_authority() {
    let config = make_config("redis://cache.internal:6379/0", false);
    let url = redis_config_url_with_ip(&config, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(url, "redis://[::1]:6379/0");
}

#[test]
fn test_url_with_resolved_ip_preserves_tls_hostname_for_sni() {
    let config = make_config("redis://cache.internal:6379/0", true);
    let url = redis_config_url_with_ip(&config, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(url, "rediss://cache.internal:6379/0");
}
