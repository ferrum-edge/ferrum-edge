use ferrum_edge::_test_support::{RedisConfig, redis_client_credentials, redis_config_url_with_ip};
use serde_json::json;
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
fn test_hostname_skips_ipv6_literals() {
    let config = make_config("redis://[2001:db8::10]:6379/0", false);
    assert_eq!(config.hostname(), None);
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

// ── ACL credential injection ─────────────────────────────────────────────
//
// Regression coverage for "Redis ACL credentials silently ignored": before
// the fix, `redis_username` / `redis_password` were parsed off the plugin
// JSON config but never forwarded to `redis::Client::open()` /
// `build_with_tls()`, so the gateway would connect unauthenticated even
// though the operator had configured ACL credentials. These tests assert
// that the credentials now flow through to `redis::ConnectionInfo`.

#[test]
fn test_explicit_credentials_are_applied_to_plain_client() {
    let mut config = make_config("redis://localhost:6379/0", false);
    config.username = Some("alice".to_string());
    config.password = Some("secret".to_string());

    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user.as_deref(), Some("alice"));
    assert_eq!(pass.as_deref(), Some("secret"));
}

#[test]
fn test_explicit_credentials_are_applied_to_tls_client() {
    let mut config = make_config("rediss://cache.internal:6379/0", true);
    config.username = Some("svc-rate-limit".to_string());
    config.password = Some("hunter2".to_string());

    // Use rediss:// + TLS so we exercise the build_with_tls branch.
    let (user, pass) =
        redis_client_credentials(config, "rediss://cache.internal:6379/0").expect("build_client");
    assert_eq!(user.as_deref(), Some("svc-rate-limit"));
    assert_eq!(pass.as_deref(), Some("hunter2"));
}

#[test]
fn test_explicit_credentials_override_url_userinfo() {
    // URL-embedded creds (`bob:fromurl`) are parsed by the redis crate, but the
    // explicit fields must take precedence so operators have a single source of
    // truth for credential rotation.
    let mut config = make_config("redis://bob:fromurl@localhost:6379/0", false);
    config.username = Some("alice".to_string());
    config.password = Some("frompayload".to_string());

    let (user, pass) = redis_client_credentials(config, "redis://bob:fromurl@localhost:6379/0")
        .expect("build_client");
    assert_eq!(user.as_deref(), Some("alice"));
    assert_eq!(pass.as_deref(), Some("frompayload"));
}

#[test]
fn test_url_userinfo_is_preserved_when_no_explicit_credentials() {
    // When neither `redis_username` nor `redis_password` is set, the URL
    // userinfo flows through (matches redis-rs' default URL parsing).
    let config = make_config("redis://carol:urlpw@localhost:6379/0", false);

    let (user, pass) = redis_client_credentials(config, "redis://carol:urlpw@localhost:6379/0")
        .expect("build_client");
    assert_eq!(user.as_deref(), Some("carol"));
    assert_eq!(pass.as_deref(), Some("urlpw"));
}

#[test]
fn test_password_only_credential() {
    // Common Redis 5 pattern: AUTH with no username, just a password.
    let mut config = make_config("redis://localhost:6379/0", false);
    config.username = None;
    config.password = Some("redis-pw".to_string());

    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user, None);
    assert_eq!(pass.as_deref(), Some("redis-pw"));
}

#[test]
fn test_no_credentials_means_unauthenticated() {
    let config = make_config("redis://localhost:6379/0", false);
    let (user, pass) =
        redis_client_credentials(config, "redis://localhost:6379/0").expect("build_client");
    assert_eq!(user, None);
    assert_eq!(pass, None);
}

#[test]
fn test_from_plugin_config_local_modes() {
    assert!(
        RedisConfig::from_plugin_config(&json!({}), "ferrum:test")
            .unwrap()
            .is_none()
    );
    assert!(
        RedisConfig::from_plugin_config(&json!({"sync_mode": "local"}), "ferrum:test")
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_from_plugin_config_rejects_invalid_redis_mode() {
    let cases = [
        json!(null),
        json!([]),
        json!({"sync_mode": false}),
        json!({"sync_mode": "redsi"}),
        json!({"sync_mode": "redis"}),
        json!({"sync_mode": "redis", "redis_url": ""}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_tls": "true"}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_key_prefix": ""}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_connect_timeout_seconds": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_health_check_interval_seconds": 0}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_username": false}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_password": []}),
    ];

    for config in cases {
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "config should fail validation: {config}"
        );
    }
}

#[test]
fn test_from_plugin_config_rejects_malformed_redis_urls() {
    for redis_url in [
        "not a url",
        "http://cache.internal:6379/0",
        "redis:///0",
        "rediss:///0",
    ] {
        let config = json!({
            "sync_mode": "redis",
            "redis_url": redis_url
        });
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "redis_url should fail validation: {redis_url}"
        );
    }
}

#[test]
fn test_from_plugin_config_parses_valid_redis_mode() {
    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_tls": true,
            "redis_key_prefix": "tenant:rate",
            "redis_pool_size": 8,
            "redis_connect_timeout_seconds": 2,
            "redis_health_check_interval_seconds": 3,
            "redis_username": "svc",
            "redis_password": "secret"
        }),
        "ferrum:test",
    )
    .unwrap()
    .unwrap();

    assert_eq!(config.url, "redis://cache.internal:6379/0");
    assert!(config.tls);
    assert_eq!(config.key_prefix, "tenant:rate");
    assert_eq!(config.pool_size, 8);
    assert_eq!(config.connect_timeout_seconds, 2);
    assert_eq!(config.health_check_interval_seconds, 3);
    assert_eq!(config.username.as_deref(), Some("svc"));
    assert_eq!(config.password.as_deref(), Some("secret"));
}
