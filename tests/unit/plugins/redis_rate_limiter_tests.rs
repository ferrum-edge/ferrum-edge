use ferrum_edge::_test_support::{
    MAX_REDIS_POOL_SIZE, RedisConfig, RedisRateLimitClient,
    create_rate_limit_plugin_with_config_id, redis_build_client, redis_client_credentials,
    redis_client_tls_insecure, redis_config_url_with_ip, redis_rate_limit_client_for_test,
};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::redis_resp::{
    TIME_CMD, TIME_DENIED_REPLY, TIME_UNKNOWN_COMMAND_REPLY, encode_server_time,
    host_clock_time_reply,
};

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

/// Connect/health-check failures log `redis_url`. `redis_url` is a documented
/// place to encode Redis ACL credentials, so the logged rendering must strip
/// userinfo while keeping scheme/host/port/db as actionable diagnostics.
#[test]
fn test_redacted_url_strips_userinfo_and_keeps_diagnostics() {
    let with_both = make_config("redis://user:pass@redis.internal:6379/15", false);
    assert_eq!(
        with_both.redacted_url(),
        "redis://redacted@redis.internal:6379/15"
    );

    let password_only = make_config("rediss://:hunter2@redis.internal:6380/0", false);
    assert_eq!(
        password_only.redacted_url(),
        "rediss://redacted@redis.internal:6380/0"
    );

    let username_only = make_config("redis://aclUser@redis.internal:6379/1", false);
    assert_eq!(
        username_only.redacted_url(),
        "redis://redacted@redis.internal:6379/1"
    );

    let suffix_secrets = make_config(
        "redis://redis.internal:6379/4?password=query-secret#fragment-secret",
        false,
    );
    assert_eq!(
        suffix_secrets.redacted_url(),
        "redis://redis.internal:6379/4"
    );

    // No userinfo: the original bytes are returned, not the parser's
    // normalization, so a credential-free URL is never silently rewritten.
    let bare = make_config("redis://Redis.Internal:6379/0", false);
    assert_eq!(bare.redacted_url(), "redis://Redis.Internal:6379/0");

    // Unparseable values cannot be proven credential-free, so they fail closed.
    let unparseable = make_config("not a url", false);
    assert_eq!(unparseable.redacted_url(), "[REDACTED]");

    // Non-Redis schemes are never safe diagnostics for a `redis_url` field —
    // even after stripping userinfo — so they fail closed wholesale.
    let http_scheme = make_config(
        "http://user:pass@collector.internal/path?token=query-secret#frag-secret",
        false,
    );
    assert_eq!(http_scheme.redacted_url(), "[REDACTED]");

    // IPv6 authorities keep diagnostics while stripping userinfo.
    let ipv6 = make_config("redis://user:pass@[2001:db8::10]:6379/2", false);
    assert_eq!(
        ipv6.redacted_url(),
        "redis://redacted@[2001:db8::10]:6379/2"
    );

    // Opaque schemes can embed secrets outside userinfo/query/fragment; they
    // must not be echoed just because the URL crate can parse them.
    let opaque = make_config("mailto:user:pass@example.com", false);
    assert_eq!(opaque.redacted_url(), "[REDACTED]");
    let data_url = make_config("data:text/plain,super-secret-token", false);
    assert_eq!(data_url.redacted_url(), "[REDACTED]");
}

/// `RedisConfig` used to derive `Debug`, which printed the ACL password and the
/// URL userinfo verbatim into any `{:?}` rendering.
#[test]
fn test_debug_rendering_hides_credentials() {
    let mut config = make_config("redis://user:urlpass@redis.internal:6379/2", false);
    config.username = Some("acl-user".to_string());
    config.password = Some("acl-password".to_string());

    let rendered = format!("{config:?}");
    assert!(
        !rendered.contains("urlpass")
            && !rendered.contains("acl-password")
            && !rendered.contains("acl-user"),
        "RedisConfig Debug leaked credentials: {rendered}"
    );
    assert!(
        rendered.contains("redis.internal:6379"),
        "RedisConfig Debug dropped useful diagnostics: {rendered}"
    );
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
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": (MAX_REDIS_POOL_SIZE as u64) + 1}),
        json!({"sync_mode": "redis", "redis_url": "redis://localhost:6379/0", "redis_pool_size": u64::MAX}),
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
        "rediss://cache.internal:6380/0#insecure",
        "rediss://cache.internal:6380/0#anything",
        "redis://cache.internal:6379/0#insecure",
        "rediss://cache.internal:6380/0#%69nsecure",
        "rediss://cache.internal:6380/0#",
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

// ── Database selector admission (issue #5005) ─────────────────────────────
//
// redis-rs derives the database from the URL path and refuses a non-integer
// selector — but only when the client is constructed, which every Redis-backed
// plugin defers to first use. `validate` therefore exited 0 on
// `redis://host/banana`, the gateway never became ready, and every correctly
// formed request was answered with a fail-closed refusal naming nothing.
// The check belongs to the shared parser, so all of its consumers get it.

/// Selectors no Redis-family server can address must be refused at admission.
#[test]
fn from_plugin_config_rejects_an_unusable_database_selector() {
    for redis_url in [
        // Not a number at all (the reported reproduction).
        "redis://cache.internal:6379/banana",
        "rediss://cache.internal:6380/banana",
        // Numeric-looking but not an integer.
        "redis://cache.internal:6379/0.5",
        "redis://cache.internal:6379/1_000",
        "redis://cache.internal:6379/%30",
        // More than one path segment: redis-rs parses the whole trimmed path.
        "redis://cache.internal:6379/0/1",
        "redis://cache.internal:6379/db/0",
        // Out of range in both directions.
        "redis://cache.internal:6379/-1",
        "redis://cache.internal:6379/2147483648",
        "redis://cache.internal:6379/9999999999",
        "redis://cache.internal:6379/00000000000",
        "redis://cache.internal:6379/00",
        "redis://cache.internal:6379/01",
        "redis://cache.internal:6379/+1",
        "redis://cache.internal:6379/1/",
        "redis://cache.internal:6379//1",
        "redis://cache.internal:6379/./1",
        "redis://cache.internal:6379/99999999999999999999",
    ] {
        let config = json!({
            "sync_mode": "redis",
            "redis_url": redis_url,
        });
        assert!(
            RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
            "redis_url must fail admission: {redis_url}"
        );
    }
}

/// The same selectors are refused while `sync_mode` is still `local`, so a later
/// toggle cannot activate a URL that admission never validated.
#[test]
fn from_plugin_config_rejects_a_latent_unusable_database_selector() {
    let config = json!({
        "sync_mode": "local",
        "redis_url": "redis://cache.internal:6379/banana",
    });
    assert!(
        RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
        "a latent unusable database selector must fail closed"
    );
}

/// Every legitimate selector shape still passes: absent, bare slash, the usual
/// small indexes, and the largest index a server could be configured for.
#[test]
fn from_plugin_config_accepts_every_usable_database_selector() {
    for redis_url in [
        "redis://cache.internal:6379",
        "redis://cache.internal:6379/",
        "redis://cache.internal:6379/0",
        "redis://cache.internal:6379/15",
        "rediss://cache.internal:6380/9",
        "redis://user:pass@cache.internal:6379/3",
        "redis://cache.internal:6379/2147483647",
        "redis://cache.internal:6379/0?protocol=resp3",
    ] {
        let config = json!({ "sync_mode": "redis", "redis_url": redis_url });
        let parsed = RedisConfig::from_plugin_config(&config, "ferrum:test")
            .unwrap_or_else(|error| panic!("{redis_url} must be admitted: {error}"));
        assert_eq!(
            parsed.map(|config| config.url),
            Some(redis_url.to_string()),
            "the admitted URL must be preserved byte-for-byte"
        );
    }
}

/// The diagnostic names the field and the accepted shape, and never echoes the
/// URL: `redis_url` is a documented place to encode ACL credentials.
#[test]
fn an_unusable_database_selector_is_diagnosed_without_echoing_the_url() {
    let secret = "super-secret-redis-pw";
    let config = json!({
        "sync_mode": "redis",
        "redis_url": format!("redis://acl:{secret}@cache.internal:6379/banana"),
    });
    let err = RedisConfig::from_plugin_config(&config, "ferrum:test")
        .err()
        .unwrap_or_else(|| {
            panic!("an unusable database selector must be rejected at construction")
        });
    assert!(
        err.contains("redis_url") && err.contains("database number"),
        "diagnostic must name the field and the accepted shape: {err}"
    );
    assert!(
        !err.contains(secret) && !err.contains("cache.internal") && !err.contains("banana"),
        "redis_url diagnostic must not echo secrets or the URL: {err}"
    );
}

/// The check lives in the shared parser, so a rate-limit consumer and a direct
/// consumer (`hmac_auth`'s shared replay authority — the reported reproduction)
/// both refuse the same URL at plugin construction instead of at first use.
#[tokio::test]
async fn every_redis_backed_plugin_refuses_an_unusable_database_selector() {
    let unusable = "redis://127.0.0.1:6379/banana";

    let err = create_rate_limit_plugin_with_config_id(
        "rate_limiting",
        &json!({
            "limits": [{ "scope": "default", "requests_per_minute": 10 }],
            "sync_mode": "redis",
            "redis_url": unusable,
        }),
        Some("rl-1"),
    )
    .err()
    .unwrap_or_else(|| panic!("rate_limiting must refuse an unusable database selector"));
    assert!(err.contains("database number"), "got: {err}");

    let err = ferrum_edge::plugins::create_plugin(
        "hmac_auth",
        &json!({
            "replay_scope": "shared",
            "sync_mode": "redis",
            "redis_url": unusable,
        }),
    )
    .err()
    .unwrap_or_else(|| panic!("hmac_auth must refuse an unusable database selector"));
    assert!(err.contains("database number"), "got: {err}");
}

/// Issue #4173: a configured exclusive CA that cannot be loaded must not
/// silently fall back to redis-rs default (system/public) roots.
#[test]
fn redis_tls_fails_closed_when_configured_ca_cannot_be_loaded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing-redis-ca.pem");
    let missing_path = missing.to_str().expect("utf8 path");
    let config = make_config("rediss://cache.internal:6380/0", true);

    let err = RedisRateLimitClient::new(config, None, false, Some(missing_path))
        .err()
        .unwrap_or_else(|| panic!("unloadable exclusive CA must refuse construction"));
    assert!(
        err.contains("exclusive CA bundle") && err.contains("refusing to fall back"),
        "diagnostic must name the fail-closed exclusive-CA decision: {err}"
    );
    assert!(
        !err.contains("using system root"),
        "must not advertise a default-root fallback: {err}"
    );
}

#[test]
fn redis_tls_constructs_when_no_ca_path_is_configured() {
    let config = make_config("rediss://cache.internal:6380/0", true);
    let client = RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(
        !client.uses_exclusive_ca_bundle_for_test(),
        "an unset CA path must keep redis-rs default roots"
    );
    redis_build_client(&client, "rediss://cache.internal:6380/0")
        .expect("default-root Redis TLS client");
}

#[test]
fn redis_tls_uses_exclusive_ca_when_the_bundle_loads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle_path = dir.path().join("redis-ca.pem");
    std::fs::write(&bundle_path, include_str!("../../certs/server.crt")).expect("write CA bundle");
    let path = bundle_path.to_str().expect("utf8 path");
    let config = make_config("rediss://cache.internal:6380/0", true);

    let client = RedisRateLimitClient::new(config, None, false, Some(path))
        .expect("a loadable exclusive CA must construct");
    assert!(
        client.uses_exclusive_ca_bundle_for_test(),
        "a loaded CA must be the sole trust anchor, not default roots"
    );
    redis_build_client(&client, "rediss://cache.internal:6380/0")
        .expect("exclusive-CA Redis TLS client");
}

#[test]
fn redis_tls_no_verify_does_not_fail_construction_on_an_unloadable_ca() {
    // FERRUM_TLS_NO_VERIFY is the sanctioned skip-verify path. Verification is
    // already off, so an unloadable CA is not a trust-policy downgrade and
    // must not change that path's construction semantics.
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing-redis-ca-noverify.pem");
    let missing_path = missing.to_str().expect("utf8 path");
    let config = make_config("rediss://cache.internal:6380/0", true);

    let client = RedisRateLimitClient::new(config, None, true, Some(missing_path))
        .expect("tls_no_verify must not fail construction on an unloadable CA");
    assert!(
        !client.uses_exclusive_ca_bundle_for_test(),
        "skip-verify must not store exclusive CA bytes it will not use"
    );
    redis_build_client(&client, "rediss://cache.internal:6380/0")
        .expect("skip-verify Redis TLS client");
}

#[test]
fn redis_exclusive_ca_load_is_the_shared_construction_gate() {
    // PR #4194 routes connect + health-check reconnect through one client
    // builder. Exclusive-CA fail-closed must stay on the load that feeds both
    // paths, not inside a connect-only helper those reconnects could bypass.
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    assert!(
        source.contains("fn load_redis_tls_ca_bundle("),
        "CA loading must live in one helper both connect paths inherit"
    );
    assert!(
        !source.contains("using system root CAs"),
        "an unloadable exclusive CA must not fall back to default roots"
    );
    assert!(
        source.matches("tls_ca_bundle_pem").count() >= 3,
        "stored exclusive CA bytes must be the input both connect paths use"
    );
}

#[test]
fn test_from_plugin_config_rejects_insecure_fragment_without_echoing_the_url() {
    // Issue #4147: a redis_url fragment is a TLS verification opt-out, not a
    // destination. Admission must fail closed without echoing userinfo or the
    // fragment itself.
    let secret = "super-secret-redis-pw";
    let config = json!({
        "sync_mode": "redis",
        "redis_url": format!("rediss://acl:{secret}@cache.internal:6380/0#insecure"),
        "redis_tls": true,
    });
    let err = RedisConfig::from_plugin_config(&config, "ferrum:test")
        .err()
        .unwrap_or_else(|| panic!("fragment-bearing redis_url must be rejected at construction"));
    assert!(
        err.contains("fragment"),
        "diagnostic must name the rejected shape: {err}"
    );
    assert!(
        !err.contains(secret) && !err.contains("#insecure") && !err.contains("cache.internal"),
        "redis_url diagnostic must not echo secrets or the URL: {err}"
    );
}

#[test]
fn test_from_plugin_config_rejects_fragment_even_in_local_mode() {
    // Latent Redis fields are validated even when sync_mode is local, so
    // toggling to redis later cannot activate a skip-verify fragment.
    let config = json!({
        "sync_mode": "local",
        "redis_url": "rediss://cache.internal:6380/0#insecure",
    });
    assert!(
        RedisConfig::from_plugin_config(&config, "ferrum:test").is_err(),
        "latent fragment-bearing redis_url must fail closed"
    );
}

#[test]
fn test_build_client_ignores_caller_insecure_fragment_unless_tls_no_verify() {
    // Belt-and-braces: even a RedisConfig constructed without from_plugin_config
    // must not honor a caller #insecure fragment. Skip-verify is only the
    // gateway-wide FERRUM_TLS_NO_VERIFY flag.
    let fragment_url = "rediss://cache.internal:6380/0#insecure";
    let config = make_config(fragment_url, true);

    let insecure = redis_client_tls_insecure(config.clone(), fragment_url, false)
        .expect("build_client with stripped fragment");
    assert!(
        !insecure,
        "caller #insecure fragment must not disable Redis TLS verification"
    );

    let sanctioned = redis_client_tls_insecure(
        make_config("rediss://cache.internal:6380/0", true),
        "rediss://cache.internal:6380/0",
        true,
    )
    .expect("FERRUM_TLS_NO_VERIFY path");
    assert!(
        sanctioned,
        "FERRUM_TLS_NO_VERIFY must still append #insecure internally"
    );

    // A caller fragment plus the sanctioned flag still skip-verifies, because
    // Ferrum strips the caller fragment and re-appends its own. Construction
    // remains the primary reject; this is the reconnect/health-check backstop.
    let both = redis_client_tls_insecure(config, fragment_url, true)
        .expect("tls_no_verify with stripped caller fragment");
    assert!(
        both,
        "FERRUM_TLS_NO_VERIFY must win after stripping a caller fragment"
    );
}

#[test]
fn test_rate_limiting_plugin_rejects_insecure_redis_url_fragment() {
    let config = json!({
        "limits": [{ "scope": "default", "requests_per_minute": 10 }],
        "sync_mode": "redis",
        "redis_url": "rediss://cache.internal:6380/0#insecure",
        "redis_tls": true,
    });
    let err = create_rate_limit_plugin_with_config_id("rate_limiting", &config, Some("rl-1"))
        .err()
        .unwrap_or_else(|| {
            panic!("rate_limiting must fail construction on a fragment-bearing redis_url")
        });
    assert!(err.contains("fragment"), "got: {err}");
    assert!(
        !err.contains("cache.internal") && !err.contains("#insecure"),
        "plugin construction must not echo redis_url: {err}"
    );
}

#[test]
fn redis_tls_skip_verify_is_applied_only_through_open_screened_redis_client() {
    // The health-check reconnect path used to duplicate the `#insecure` append
    // (and the `!url.contains('#')` guard that let a caller fragment through).
    // Both paths must share open_screened_redis_client, which strips first.
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    assert!(
        source.contains("fn open_screened_redis_client("),
        "Redis TLS client construction must go through one helper"
    );
    assert!(
        source.contains("format!(\"{without_fragment}#insecure\")"),
        "skip-verify must append #insecure only after stripping any caller fragment"
    );
    assert!(
        !source.contains("&& !url.contains('#')"),
        "the old contains('#') guard let a caller #insecure fragment through"
    );
    let helper_calls = source.matches("open_screened_redis_client(").count();
    assert!(
        helper_calls >= 3,
        "build_client and the health-check reconnect must both call the helper; got {helper_calls}"
    );
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

#[test]
fn test_from_plugin_config_accepts_exact_max_redis_pool_size() {
    // Inclusive upper bound: redis_pool_size == MAX_REDIS_POOL_SIZE must parse
    // and be preserved exactly (MAX+1 / u64::MAX remain covered by rejection cases).
    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": "redis://localhost:6379/0",
            "redis_pool_size": MAX_REDIS_POOL_SIZE,
        }),
        "ferrum:test",
    )
    .expect("exact MAX_REDIS_POOL_SIZE must be accepted")
    .expect("sync_mode=redis must yield Some(RedisConfig)");

    assert_eq!(config.pool_size, MAX_REDIS_POOL_SIZE);
}

// ── Connection-attempt timeout wiring (issue #2310) ───────────────────────
//
// redis-rs 1.2.1 defaults `AsyncConnectionConfig` timeouts to one second.
// Ferrum must install `redis_connect_timeout_seconds` into that inner config so
// values above one second are effective. `AsyncConnectionConfig` exposes no
// getter, so the wiring is pinned by source text plus the outer-bound value.
// Assertions below are outcome-based (success/failure / config equality), not
// wall-clock ranges.

#[test]
fn connect_timeout_is_installed_into_redis_connection_config_above_and_below_one_second() {
    for seconds in [1_u64, 2, 5, 30] {
        let mut config = make_config("redis://127.0.0.1:6379/0", false);
        config.connect_timeout_seconds = seconds;
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.connection_timeout_for_test(),
            Duration::from_secs(seconds)
        );
    }

    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    let pooled_config = "screened_async_connection_config(self.connect_timeout())";
    let shared_helper = ".set_connection_timeout(Some(connect_timeout))";
    assert!(
        source.contains(pooled_config),
        "inner AsyncConnectionConfig must carry Ferrum's timeout, not the crate 1s default"
    );
    assert!(
        source.contains(shared_helper),
        "the shared connection-config helper must install Ferrum's connect timeout"
    );
    // Issue #5006: the pooled and dedicated paths dial with the crate's 500ms
    // command cap disabled so the INFO screens get the configured deadline, then
    // re-arm a bounded per-command deadline before the connection is published.
    let rearm = "conn.set_response_timeout(SCREENED_COMMAND_RESPONSE_TIMEOUT);";
    assert!(
        source.contains(rearm),
        "a screened connection must be re-armed with a bounded command deadline"
    );
    let screened_sites = source.matches("self.screen_and_arm(&mut conn)").count();
    assert_eq!(
        screened_sites, 2,
        "both the pooled and the dedicated connect paths must screen and re-arm"
    );
}

#[test]
fn recovery_ping_is_bounded_by_the_connect_timeout() {
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    assert!(
        source.contains("async fn ping_connection("),
        "recovery PING must go through a bounded helper"
    );
    assert!(
        source.contains("ping_connection(&mut conn, connect_timeout)"),
        "the recovery checker must bound PING by redis_connect_timeout_seconds"
    );
    assert!(
        source.contains(".set_response_timeout(None)"),
        "recovery connections must disable redis-rs' 500ms response timeout"
    );
    assert!(
        source.contains("error.is_timeout()"),
        "an inner I/O timeout on recovery PING must use the classified ping-timeout error"
    );
    assert!(
        !source.contains("redis::cmd(\"PING\").query_async::<String>(&mut conn).await"),
        "unbounded recovery PING must not return"
    );
}

/// Accept TCP, optionally delay, then answer every RESP array command with
/// `+OK` — except the standalone `TIME` probe, which gets this host's clock.
///
/// Used to simulate a Redis endpoint whose protocol handshake is delayed after
/// TCP accept (the failure mode in issue #2310).
///
/// Framing is exact rather than a `*`-byte count, because `TIME` now has to be
/// told apart from the rest: a `+OK` answer to it is a reply the client cannot
/// pair with a clock, so it drops the connection unpublished and no pool slot
/// is ever established. See [`super::redis_resp`].
async fn spawn_delayed_redis_handshake_server(
    handshake_delay: Option<Duration>,
) -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let delay = handshake_delay;
                    tokio::spawn(async move {
                        if let Some(delay) = delay {
                            tokio::time::sleep(delay).await;
                        }
                        let mut buf = vec![0_u8; 4096];
                        let mut pending: Vec<u8> = Vec::new();
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            let mut reply = Vec::new();
                            // Exactly one reply per fully received command, so
                            // the client's in-flight accounting always matches
                            // even when the redis crate pipelines its setup.
                            while let Some((name, consumed)) = parse_resp_command(&pending) {
                                pending.drain(..consumed);
                                if name == "TIME" {
                                    reply.extend_from_slice(&host_clock_time_reply());
                                } else {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if reply.is_empty() {
                                continue;
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, accepts)
}

#[tokio::test]
async fn connect_timeout_above_one_second_allows_delayed_redis_handshake() {
    // Handshake completes after >1s. With the buggy crate default (1s) this
    // fails; with Ferrum's configured 5s inner timeout it must succeed.
    let (port, shutdown, _accepts) =
        spawn_delayed_redis_handshake_server(Some(Duration::from_millis(1500))).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert!(
        client.connect_cached_for_test().await,
        "cached path must honor redis_connect_timeout_seconds > 1s"
    );

    // Fresh client for the dedicated path (the pooled connection is already warm).
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let dedicated = redis_rate_limit_client_for_test(config);
    assert!(
        dedicated.connect_dedicated_for_test().await,
        "dedicated path must honor redis_connect_timeout_seconds > 1s"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let health = redis_rate_limit_client_for_test(config);
    assert!(
        health.health_check_connect_for_test().await,
        "health-check path must honor redis_connect_timeout_seconds > 1s"
    );

    let _ = shutdown.send(());
}

#[tokio::test]
async fn connect_timeout_of_one_second_fails_closed_on_hung_handshake() {
    // Accept, then delay the Redis protocol reply far beyond the configured
    // timeout. A 1s Ferrum timeout must fail closed on every path. Outcomes
    // only — no elapsed-time assertions.
    let (port, shutdown, accepts) =
        spawn_delayed_redis_handshake_server(Some(Duration::from_secs(30))).await;

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);
    assert!(
        !client.connect_cached_for_test().await,
        "cached path must fail closed when handshake exceeds 1s timeout"
    );
    assert!(
        !client.is_available(),
        "failed connect must mark Redis unavailable for local fallback"
    );
    assert!(
        accepts.load(Ordering::Relaxed) >= 1,
        "server must have accepted at least one dial attempt"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let dedicated = redis_rate_limit_client_for_test(config);
    assert!(
        !dedicated.connect_dedicated_for_test().await,
        "dedicated path must fail closed when handshake exceeds 1s timeout"
    );

    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 1;
    config.health_check_interval_seconds = 60;
    let health = redis_rate_limit_client_for_test(config);
    assert!(
        !health.health_check_connect_for_test().await,
        "health-check path must fail closed when handshake exceeds 1s timeout"
    );

    let _ = shutdown.send(());
}

#[test]
fn plugin_consumers_parse_connect_timeout_above_one_second() {
    // rate_limiting / graphql / grpc_method_router all share RedisConfig parsing.
    // Prove each consumer's documented default prefix + a >1s timeout parses.
    for (prefix, seconds) in [
        ("ferrum:rate_limiting", 5_u64),
        ("ferrum:graphql", 2_u64),
        ("ferrum:grpc_method_router", 10_u64),
    ] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_connect_timeout_seconds": seconds,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        assert_eq!(config.connect_timeout_seconds, seconds);
        assert_eq!(config.key_prefix, prefix);
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.connection_timeout_for_test(),
            Duration::from_secs(seconds)
        );
    }
}

// ── redis_pool_size cardinality / selection (issue #2304) ─────────────────
//
// Before the fix, `redis_pool_size` was parsed and validated but every instance
// cached exactly one connection. These tests prove configured pool size controls
// runtime cardinality and round-robin selection — not merely parsing.

#[test]
fn pool_size_controls_client_cardinality_for_named_consumers() {
    // rate_limiting / graphql / grpc_method_router all construct RedisRateLimitClient
    // through RedisConfig / RateLimitBackend::from_plugin_config.
    for (prefix, pool_size) in [
        ("ferrum:rate_limiting", 1_usize),
        ("ferrum:graphql", 3_usize),
        ("ferrum:grpc_method_router", 8_usize),
    ] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_pool_size": pool_size,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        assert_eq!(config.pool_size, pool_size);
        assert_eq!(config.key_prefix, prefix);
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(
            client.pool_size_for_test(),
            pool_size,
            "client pool must match redis_pool_size for {prefix}"
        );
        assert_eq!(
            client.cached_pool_cardinality_for_test(),
            0,
            "pool slots must be empty before lazy establishment"
        );
    }
}

#[test]
fn pool_slot_selection_is_deterministic_round_robin() {
    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.pool_size = 4;
    let client = redis_rate_limit_client_for_test(config);
    assert_eq!(
        client.select_slot_indexes_for_test(10),
        vec![0, 1, 2, 3, 0, 1, 2, 3, 0, 1]
    );

    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.pool_size = 1;
    let single = redis_rate_limit_client_for_test(config);
    assert_eq!(single.select_slot_indexes_for_test(5), vec![0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn pool_size_one_establishes_single_tcp_connection() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 1;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 1);
    assert_eq!(client.cached_pool_cardinality_for_test(), 1);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "pool_size=1 must open exactly one multiplexed TCP connection"
    );

    // Re-warming must reuse the cached connection, not dial again.
    assert_eq!(client.warm_pool_for_test().await, 1);
    assert_eq!(accepts.load(Ordering::Relaxed), 1);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn pool_size_four_establishes_four_tcp_connections() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 4;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 4);
    assert_eq!(client.cached_pool_cardinality_for_test(), 4);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        4,
        "pool_size=4 must open four multiplexed TCP connections"
    );

    // Second warm must reuse all slots.
    assert_eq!(client.warm_pool_for_test().await, 4);
    assert_eq!(accepts.load(Ordering::Relaxed), 4);
    assert_eq!(client.cached_pool_cardinality_for_test(), 4);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn pool_clear_on_reconnect_drops_all_slots_then_reestablishes() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.pool_size = 3;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(accepts.load(Ordering::Relaxed), 3);

    // Reconnect clearing must wipe every slot (partial-failure / mark_unavailable path).
    client.clear_pool_for_test();
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        6,
        "after clear, all three slots must dial again"
    );
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);

    let _ = shutdown.send(());
}

#[tokio::test]
async fn named_consumer_pool_sizes_produce_matching_tcp_cardinality() {
    // End-to-end for the three issue-named consumers: parse their config shape,
    // construct the shared client, and prove TCP accepts == redis_pool_size.
    for (prefix, pool_size) in [
        ("ferrum:rate_limiting", 2_usize),
        ("ferrum:graphql", 5_usize),
        ("ferrum:grpc_method_router", 3_usize),
    ] {
        let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": format!("redis://127.0.0.1:{port}/0"),
                "redis_pool_size": pool_size,
                "redis_health_check_interval_seconds": 60,
            }),
            prefix,
        )
        .expect("parse")
        .expect("redis mode");
        let client = redis_rate_limit_client_for_test(config);
        assert_eq!(client.pool_size_for_test(), pool_size);
        assert_eq!(client.warm_pool_for_test().await, pool_size);
        assert_eq!(
            accepts.load(Ordering::Relaxed),
            pool_size,
            "{prefix}: TCP accepts must equal redis_pool_size={pool_size}"
        );
        assert_eq!(client.cached_pool_cardinality_for_test(), pool_size);
        let _ = shutdown.send(());
    }
}

#[test]
fn rate_limit_backend_from_plugin_config_honors_pool_size_for_named_consumers() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };

    let http = PluginHttpClient::default();
    let algorithm = DynamicHttpRateLimitAlgorithm::new();

    for (plugin_name, pool_size) in [
        ("rate_limiting", 1_usize),
        ("graphql", 4_usize),
        ("grpc_method_router", 7_usize),
    ] {
        let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
            RateLimitBackend::from_plugin_config(
                plugin_name,
                &json!({
                    "sync_mode": "redis",
                    "redis_url": "redis://127.0.0.1:6379/0",
                    "redis_pool_size": pool_size,
                    "redis_health_check_interval_seconds": 60,
                }),
                &http,
                algorithm,
            )
            .expect("failover backend");
        assert!(matches!(backend, RateLimitBackend::Failover(_)));
        assert_eq!(
            backend.redis_pool_size_for_test(),
            Some(pool_size),
            "{plugin_name}: RateLimitBackend must retain redis_pool_size"
        );
    }

    let local: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({"sync_mode": "local"}),
            &http,
            algorithm,
        )
        .expect("local backend");
    assert_eq!(local.redis_pool_size_for_test(), None);
}

// ── Sliding-window subsecond precision (issue #2303) ──────────────────────
//
// Before the fix, `elapsed_fraction` used whole epoch seconds, so a one-second
// window always reported fraction 0.0 and never decayed the previous bucket.
// Index and fraction also used separate clock reads that could straddle a
// boundary. Coverage below is pure/deterministic via `window_progress_at`.

#[test]
fn window_progress_one_second_start_midpoint_and_end() {
    use ferrum_edge::_test_support::redis_window_progress_at;

    let start = redis_window_progress_at(Duration::from_secs(100), 1);
    assert_eq!(start.index, 100);
    assert_eq!(start.elapsed_fraction, 0.0);

    let mid = redis_window_progress_at(Duration::from_millis(100_500), 1);
    assert_eq!(mid.index, 100);
    assert!((mid.elapsed_fraction - 0.5).abs() < 1e-12);

    let near_end = redis_window_progress_at(Duration::from_nanos(100_999_999_999), 1);
    assert_eq!(near_end.index, 100);
    assert!(near_end.elapsed_fraction > 0.999);
    assert!(near_end.elapsed_fraction < 1.0);

    let boundary = redis_window_progress_at(Duration::from_secs(101), 1);
    assert_eq!(boundary.index, 101);
    assert_eq!(boundary.elapsed_fraction, 0.0);
}

#[test]
fn window_progress_multi_second_start_midpoint_and_end() {
    use ferrum_edge::_test_support::redis_window_progress_at;

    let start = redis_window_progress_at(Duration::from_secs(10), 5);
    assert_eq!(start.index, 2);
    assert_eq!(start.elapsed_fraction, 0.0);

    let mid = redis_window_progress_at(Duration::from_millis(12_500), 5);
    assert_eq!(mid.index, 2);
    assert!((mid.elapsed_fraction - 0.5).abs() < 1e-12);

    let near_end = redis_window_progress_at(Duration::from_nanos(14_999_999_999), 5);
    assert_eq!(near_end.index, 2);
    assert!(near_end.elapsed_fraction > 0.999);
    assert!(near_end.elapsed_fraction < 1.0);

    let boundary = redis_window_progress_at(Duration::from_secs(15), 5);
    assert_eq!(boundary.index, 3);
    assert_eq!(boundary.elapsed_fraction, 0.0);
}

#[test]
fn window_progress_rejects_former_boundary_straddle_mismatch() {
    use ferrum_edge::_test_support::redis_window_progress_at;

    // Instant just before a 5s boundary vs the next instant: each sample must
    // stay internally consistent. The old bug could pair index from t0 with
    // fraction from t1 (index=2 with fraction=0.0) and under-decay the prior
    // bucket.
    let before = redis_window_progress_at(Duration::from_millis(14_999), 5);
    let after = redis_window_progress_at(Duration::from_secs(15), 5);
    assert_eq!(before.index, 2);
    assert!(before.elapsed_fraction > 0.99);
    assert_eq!(after.index, 3);
    assert_eq!(after.elapsed_fraction, 0.0);

    // A single captured sample never yields the mismatched (index=2, frac=0.0)
    // pairing that separate clock reads produced across this boundary.
    assert!(
        !(before.index == 2 && before.elapsed_fraction == 0.0),
        "pre-boundary sample must not report a zero fraction with the prior index"
    );
}

#[test]
fn redis_one_second_prior_bucket_decays_instead_of_full_suppression() {
    use ferrum_edge::_test_support::redis_window_progress_at;
    use ferrum_edge::plugins::utils::rate_limit::FixedWindow;

    // TOKEN-ACCOUNTING path only (`ai_rate_limiter` budgets, `ws_rate_limiting`
    // frames): prev bucket full (10), current has the candidate request (1). At
    // fraction 0.0 the old code always denied; with subsecond decay the
    // mid-window candidate is admitted. Request quotas moved off this estimate
    // onto the sub-bucket ladder covered below.
    let window = FixedWindow::new(10, 1);
    let start = redis_window_progress_at(Duration::from_secs(50), 1);
    let mid = redis_window_progress_at(Duration::from_millis(50_500), 1);
    let near_end = redis_window_progress_at(Duration::from_nanos(50_900_000_000), 1);

    assert!(
        !window.outcome(10, 1, start.elapsed_fraction).allowed,
        "at window start a full prior bucket still suppresses (weighted=11)"
    );
    assert!(
        window.outcome(10, 1, mid.elapsed_fraction).allowed,
        "mid one-second window must decay prior bucket (weighted=6)"
    );
    assert!(
        window.outcome(10, 1, near_end.elapsed_fraction).allowed,
        "near end of one-second window prior bucket is nearly gone"
    );
    assert!(
        (window.weighted_count(10, 0, mid.elapsed_fraction) - 5.0).abs() < 1e-12,
        "half-elapsed prior bucket of 10 contributes exactly 5"
    );
}

// ── Request-quota sub-bucket ladder ──────────────────────────────────────
//
// Request quotas (`rate_limiting`, `graphql`, `grpc_method_router`) count a
// sub-bucketed trailing window in full instead of decaying a previous epoch
// bucket. Coverage below is pure/deterministic via `sub_bucket_at`,
// `window_charge`, and `redis_trailing_window_count`.

#[test]
fn sub_bucket_index_splits_each_window_into_equal_parts() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKET_KEYS, REDIS_WINDOW_SUB_BUCKETS, REDIS_WINDOW_TRAILING_SUB_BUCKETS,
        RedisRateLimitClient, redis_sub_bucket_nanos,
    };

    assert_eq!(REDIS_WINDOW_SUB_BUCKETS, 16, "the key layout pins K");
    assert_eq!(
        REDIS_WINDOW_TRAILING_SUB_BUCKETS,
        REDIS_WINDOW_SUB_BUCKETS + 1,
        "the ladder reads ONE sub-bucket further back than the window itself, \
         because a retained charge's key can be one bucket older than the bucket \
         the server executed it in"
    );
    assert_eq!(
        REDIS_WINDOW_SUB_BUCKET_KEYS,
        REDIS_WINDOW_SUB_BUCKETS + 3,
        "K + 1 older, the charged bucket, and the forward bucket"
    );

    // One-second window → 62.5ms sub-buckets.
    let at = |millis: u64, window: u64| {
        RedisRateLimitClient::sub_bucket_at(Duration::from_millis(millis), window)
    };
    assert_eq!(at(100_000, 1).index, 1_600);
    assert_eq!(at(100_062, 1).index, 1_600);
    assert_eq!(at(100_063, 1).index, 1_601);
    assert_eq!(at(100_999, 1).index, 1_615);
    assert_eq!(at(101_000, 1).index, 1_616);

    // Sixty-second window → 3.75s sub-buckets; a whole window is exactly K of
    // them, which is what makes `current + K older` cover the trailing window.
    assert_eq!(at(600_000, 60).index, 160);
    assert_eq!(at(603_749, 60).index, 160);
    assert_eq!(at(603_750, 60).index, 161);
    assert_eq!(at(660_000, 60).index - at(600_000, 60).index, 16);

    // The width helper the key builder and the quarantine threshold share.
    assert_eq!(redis_sub_bucket_nanos(1), 62_500_000);
    assert_eq!(redis_sub_bucket_nanos(60), 3_750_000_000);
    assert_eq!(redis_sub_bucket_nanos(0), redis_sub_bucket_nanos(1));

    // The window travels with the index because it is a key component.
    assert_eq!(at(100_000, 60).window_seconds, 60);
    // A zero window is clamped to one second rather than dividing by zero.
    assert_eq!(at(100_000, 0).window_seconds, 1);
    assert_eq!(at(100_000, 0).index, 1_600);
}

#[test]
fn window_charge_keys_share_a_hash_tag_and_name_their_window() {
    use ferrum_edge::plugins::utils::rate_limit::two_window_ttl_seconds;
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKET_KEYS, REDIS_WINDOW_TRAILING_SUB_BUCKETS, RedisRateLimitClient,
    };

    let client = redis_rate_limit_client_for_test(make_config("redis://127.0.0.1:6379/0", false));
    let bucket = RedisRateLimitClient::sub_bucket_at(Duration::from_secs(100), 1);
    let charge = client.window_charge("ip:127.0.0.1", bucket, two_window_ttl_seconds(1));

    // `%`, braces, and `:` are percent-escaped inside the tag so a
    // caller-controlled identity cannot terminate it early.
    let tag = "{ferrum%3Atest:ip%3A127.0.0.1}";
    let trailing: Vec<&str> = charge.trailing_keys().collect();
    assert_eq!(trailing.len(), REDIS_WINDOW_TRAILING_SUB_BUCKETS);
    // `K + 1` back, not `K`: the oldest counter is one sub-bucket further back
    // than the window itself, which is what keeps a peer's retained charge
    // inside this ladder when its key is one bucket older than the bucket the
    // server executed it in.
    assert_eq!(trailing[0], format!("{tag}:1:1583"));
    assert_eq!(trailing[16], format!("{tag}:1:1599"));
    assert_eq!(charge.charged_key(), format!("{tag}:1:1600"));
    // The forward counter: read, never written, and what makes two reordered
    // transactions on either side of a boundary see each other.
    assert_eq!(charge.next_key(), format!("{tag}:1:1601"));
    assert_eq!(charge.legacy_previous_key(), format!("{tag}:99"));
    assert_eq!(charge.legacy_current_key(), format!("{tag}:100"));
    assert_eq!(
        charge.bucket(),
        RedisRateLimitClient::sub_bucket_at(Duration::from_secs(100), 1),
        "the charge carries the bucket it selected, for the post-EXEC check"
    );

    // Retention outlives the `window + two sub-buckets` of history the ladder
    // reads back, so the oldest bucket a decision needs is never expired first.
    assert_eq!(charge.ttl_seconds(), 3);

    // Every key of one transaction hashes to the same slot.
    let charged = charge.charged_key();
    for key in trailing.iter().copied().chain([
        charged,
        charge.next_key(),
        charge.legacy_previous_key(),
        charge.legacy_current_key(),
    ]) {
        assert!(key.starts_with(tag), "{key} must carry the shared hash tag");
    }

    // Nineteen distinct keys, never a repeat that would double-count one
    // counter.
    let mut distinct: Vec<&str> = trailing
        .iter()
        .copied()
        .chain([charged, charge.next_key()])
        .collect();
    assert_eq!(distinct.len(), REDIS_WINDOW_SUB_BUCKET_KEYS);
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), REDIS_WINDOW_SUB_BUCKET_KEYS);

    // Two windows of one policy are disjoint ladders because the key names the
    // window, not only its index.
    let minute = RedisRateLimitClient::sub_bucket_at(Duration::from_secs(100), 60);
    let minute_charge = client.window_charge("ip:127.0.0.1", minute, two_window_ttl_seconds(60));
    assert_eq!(minute_charge.charged_key(), format!("{tag}:60:26"));
    assert_ne!(minute_charge.charged_key(), charge.charged_key());
}

#[test]
fn trailing_window_count_sums_every_sub_bucket_in_full() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKET_KEYS, REDIS_WINDOW_TRAILING_SUB_BUCKETS,
        redis_trailing_window_count,
    };

    // No decay term: a burst clustered in the OLDEST sub-bucket of a full
    // ladder still counts for everything it is worth.
    let mut ladder = [None; REDIS_WINDOW_SUB_BUCKET_KEYS];
    ladder[0] = Some(100);
    ladder[REDIS_WINDOW_TRAILING_SUB_BUCKETS] = Some(1);
    assert_eq!(redis_trailing_window_count(&ladder), 101);

    // A missing key is zero usage, not an error.
    assert_eq!(redis_trailing_window_count(&[None, None, Some(7)]), 7);

    // A counter can only go negative when a compensating DECR raced its key's
    // expiry. Flooring each bucket on its own keeps that stale key from
    // cancelling a live burst in another bucket.
    let raced = [Some(-5), Some(100), Some(1)];
    assert_eq!(redis_trailing_window_count(&raced), 101);

    // Saturating, because a wrapped total would read as spare budget. Two
    // `i64::MAX` buckets land one short of `u64::MAX`; the third proves the
    // clamp rather than a wrap back to a tiny, admissible total.
    let huge = [Some(i64::MAX), Some(i64::MAX)];
    assert_eq!(redis_trailing_window_count(&huge), u64::MAX - 1);
    let huger = [Some(i64::MAX), Some(i64::MAX), Some(i64::MAX)];
    assert_eq!(redis_trailing_window_count(&huger), u64::MAX);

    assert_eq!(redis_trailing_window_count(&[]), 0);
}

/// What one modelled decision did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ModelDecision {
    /// The trailing-window total the settled ladder summed, this request's own
    /// charge included. `None` when two passes could not settle and the
    /// decision failed closed the way `check_http_windows_redis` does.
    counted: Option<u64>,
    admitted: bool,
}

/// Deterministic model of ONE identity's Redis request-quota decisions, driven
/// by synthetic timestamps through the production sub-bucket derivation and the
/// production fold.
///
/// `buckets` stands in for the Redis keyspace; admission is charge-then-compare
/// and a refusal hands its own charge straight back, exactly like
/// `check_http_windows_redis`.
///
/// Selection and execution are SEPARATE instants: a request selects its bucket
/// at `selected_at` and the server applies the transaction `latency` later.
/// That is the production shape, and modelling both with one instant is what
/// hid the reader's own placement lag — a charge is keyed at the bucket it
/// SELECTED while the reader counts history from the bucket it EXECUTES in, and
/// settlement deliberately admits a one-bucket gap between the two. Two passes,
/// and a second mis-settlement fails closed, exactly like
/// `MAX_REDIS_CHARGE_PASSES`.
fn model_sub_bucket_decision(
    buckets: &mut std::collections::HashMap<u64, i64>,
    selected_at: Duration,
    latency: Duration,
    window_seconds: u64,
    limit: u64,
) -> ModelDecision {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKET_KEYS, REDIS_WINDOW_TRAILING_SUB_BUCKETS, RedisRateLimitClient,
        redis_trailing_window_count, sub_bucket_charge_is_settled,
    };

    let mut selected_at = selected_at;
    for pass in 0..2 {
        let bucket = RedisRateLimitClient::sub_bucket_at(selected_at, window_seconds);
        let charged = bucket.index;
        *buckets.entry(charged).or_insert(0) += 1;
        let executed_at = selected_at.saturating_add(latency);
        if !sub_bucket_charge_is_settled(bucket, executed_at) {
            // Hand the abandoned charge back and rebuild from the instant the
            // server proved the rollover, exactly like production.
            *buckets.entry(charged).or_insert(0) -= 1;
            if pass == 1 {
                return ModelDecision {
                    counted: None,
                    admitted: false,
                };
            }
            selected_at = executed_at;
            continue;
        }
        // Same ladder shape production builds: the `K + 1` older sub-buckets,
        // the charged one, and the one after it. A single-client ordered
        // timeline never charges ahead of the clock, so the forward counter is
        // always empty here — it exists for concurrent/reordered execution,
        // which
        // `a_reordered_transaction_across_a_sub_bucket_boundary_cannot_double_admit`
        // covers against a real server.
        let mut ladder = [None; REDIS_WINDOW_SUB_BUCKET_KEYS];
        for (slot, value) in ladder.iter_mut().enumerate() {
            let index = if slot > REDIS_WINDOW_TRAILING_SUB_BUCKETS {
                charged.saturating_add((slot - REDIS_WINDOW_TRAILING_SUB_BUCKETS) as u64)
            } else {
                charged.saturating_sub((REDIS_WINDOW_TRAILING_SUB_BUCKETS - slot) as u64)
            };
            *value = buckets.get(&index).copied();
        }
        let counted = redis_trailing_window_count(&ladder);
        if counted > limit {
            *buckets.entry(charged).or_insert(0) -= 1;
            return ModelDecision {
                counted: Some(counted),
                admitted: false,
            };
        }
        return ModelDecision {
            counted: Some(counted),
            admitted: true,
        };
    }
    unreachable!("the loop returns on both passes")
}

/// [`model_sub_bucket_decision`] reduced to the admission bit, for the timeline
/// sweeps that only care whether a request got through.
fn model_sub_bucket_admits(
    buckets: &mut std::collections::HashMap<u64, i64>,
    selected_at: Duration,
    latency: Duration,
    window_seconds: u64,
    limit: u64,
) -> bool {
    model_sub_bucket_decision(buckets, selected_at, latency, window_seconds, limit).admitted
}

/// The retired two-window weighted estimate, for the same synthetic timeline.
fn model_weighted_admits(
    windows: &mut std::collections::HashMap<u64, i64>,
    now: Duration,
    window_seconds: u64,
    limit: u64,
) -> bool {
    use ferrum_edge::_test_support::redis_window_progress_at;

    let progress = redis_window_progress_at(now, window_seconds);
    let index = progress.index;
    *windows.entry(index).or_insert(0) += 1;
    let previous = windows.get(&index.saturating_sub(1)).copied().unwrap_or(0);
    let current = windows.get(&index).copied().unwrap_or(0);
    let weighted = previous as f64 * (1.0 - progress.elapsed_fraction) + current as f64;
    if weighted > limit as f64 {
        *windows.entry(index).or_insert(0) -= 1;
        return false;
    }
    true
}

/// The retired bare `previous + current` sum, for the same synthetic timeline.
fn model_two_bucket_admits(
    windows: &mut std::collections::HashMap<u64, i64>,
    now: Duration,
    window_seconds: u64,
    limit: u64,
) -> bool {
    use ferrum_edge::_test_support::redis_window_progress_at;

    let index = redis_window_progress_at(now, window_seconds).index;
    *windows.entry(index).or_insert(0) += 1;
    let previous = windows.get(&index.saturating_sub(1)).copied().unwrap_or(0);
    let current = windows.get(&index).copied().unwrap_or(0);
    let usage = previous.max(0) as u64 + current.max(0) as u64;
    if usage > limit {
        *windows.entry(index).or_insert(0) -= 1;
        return false;
    }
    true
}

#[test]
fn boundary_clustered_burst_stays_counted_inside_the_trailing_window() {
    // 100/second. The attacker spends its whole quota at the very END of epoch
    // second 10, then comes back half a second later. The exact trailing second
    // at t = 11.5s still contains all 100 of those requests, so nothing more may
    // be admitted until they age out.
    let mut buckets = std::collections::HashMap::new();
    let mut weighted = std::collections::HashMap::new();
    for offset in 0..100_u64 {
        let at = Duration::from_micros(10_900_000 + offset);
        assert!(
            model_sub_bucket_admits(&mut buckets, at, Duration::ZERO, 1, 100),
            "the burst itself is within budget"
        );
        assert!(model_weighted_admits(&mut weighted, at, 1, 100));
    }

    assert!(
        !model_sub_bucket_admits(
            &mut buckets,
            Duration::from_millis(11_500),
            Duration::ZERO,
            1,
            100
        ),
        "a burst still inside the exact trailing second must be counted in full"
    );
    // The vulnerability this replaces: the weighted estimate assumed the burst
    // was spread evenly through second 10, so at half-elapsed it discounted
    // half of it and re-opened the budget while every request was still live.
    assert!(
        model_weighted_admits(&mut weighted, Duration::from_millis(11_500), 1, 100),
        "the retired weighted estimate admitted a second burst here"
    );

    // Once the burst has aged past the trailing window the budget is free
    // again: this is a trailing-window limiter, not a lockout.
    assert!(
        model_sub_bucket_admits(
            &mut buckets,
            Duration::from_millis(12_200),
            Duration::ZERO,
            1,
            100
        ),
        "a burst outside the trailing window must stop counting"
    );
}

#[test]
fn steady_traffic_at_the_configured_rate_is_not_halved() {
    // Exactly 20 requests per second against a 20/second quota, for six
    // seconds, with no placement lag. A homogeneous stream over-refuses by at
    // most two sub-buckets of history — up to `ceil(2 * limit / K)` = 3
    // requests here — so the client keeps about `20 / 23` of its rate; the
    // documented BOUND allows three sub-buckets (`ceil(3 * limit / K)` = 4, so
    // `20 / 24`) for a reader whose own placement lag straddles a boundary. The
    // bare `previous + current` sum this replaces counts up to two whole
    // windows and settles at half for EVERY limit. The exact per-limit
    // quantisation, including the small quotas where it costs most, is pinned
    // by `steady_traffic_pays_the_documented_sub_bucket_quantisation`.
    let offered = 120_u64;
    let mut buckets = std::collections::HashMap::new();
    let mut two_bucket = std::collections::HashMap::new();
    let mut sub_bucket_admitted = 0_u64;
    let mut two_bucket_admitted = 0_u64;
    for attempt in 0..offered {
        let at = Duration::from_millis(600_000 + attempt * 50);
        if model_sub_bucket_admits(&mut buckets, at, Duration::ZERO, 1, 20) {
            sub_bucket_admitted += 1;
        }
        if model_two_bucket_admits(&mut two_bucket, at, 1, 20) {
            two_bucket_admitted += 1;
        }
    }

    // Steady state is about 20 * 20/23 ≈ 17.4 per second after the first window
    // fills; 95/120 is the floor that separates it from the halved shape.
    assert!(
        sub_bucket_admitted >= 95,
        "steady traffic at the configured rate must not be throttled: \
         {sub_bucket_admitted}/{offered}"
    );
    assert!(
        sub_bucket_admitted <= offered,
        "the quota must still bind: {sub_bucket_admitted}/{offered}"
    );
    // Root's finding: `previous + current` refuses for a whole window after any
    // window that reached its limit, which is about half the configured quota.
    assert!(
        two_bucket_admitted <= 75,
        "the retired two-bucket sum halves a well-behaved client: \
         {two_bucket_admitted}/{offered}"
    );
    assert!(
        sub_bucket_admitted > two_bucket_admitted + 20,
        "{sub_bucket_admitted} vs {two_bucket_admitted}"
    );
}

#[test]
fn sub_bucket_ladder_never_admits_more_than_the_exact_trailing_window() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKETS, REDIS_WINDOW_TRAILING_SUB_BUCKETS, RedisRateLimitClient,
        redis_sub_bucket_nanos,
    };

    // Fail-closed property, swept across every sub-bucket phase of a one-second
    // window: whatever the arrival pattern, the admissions inside ANY exact
    // trailing second never exceed the configured cap. Microseconds, because a
    // one-second window's sub-bucket is 62.5ms and does not divide into
    // milliseconds.
    let limit = 20_u64;
    for phase in 0..REDIS_WINDOW_SUB_BUCKETS as u64 {
        let mut buckets = std::collections::HashMap::new();
        let mut admitted_at: Vec<u64> = Vec::new();
        for attempt in 0..400_u64 {
            // Bursty arrivals: eight back-to-back requests every 40ms, offset
            // into the ladder by `phase` sub-buckets.
            let micros = 600_000_000 + phase * 62_500 + (attempt / 8) * 40_000;
            if model_sub_bucket_admits(
                &mut buckets,
                Duration::from_micros(micros),
                Duration::ZERO,
                1,
                limit,
            ) {
                admitted_at.push(micros);
            }
        }
        for window_end in &admitted_at {
            let inside = admitted_at
                .iter()
                .filter(|at| **at > window_end.saturating_sub(1_000_000) && *at <= window_end)
                .count() as u64;
            assert!(
                inside <= limit,
                "phase {phase}: {inside} admissions inside the second ending at {window_end}"
            );
        }
        assert!(
            !admitted_at.is_empty(),
            "phase {phase} must still admit traffic"
        );
    }

    // The derivation the sweep rests on: the `K + 1` older sub-buckets plus the
    // charged one span a whole window AND one sub-bucket more, which is the
    // extra history that keeps a peer's one-bucket-older key inside the ladder.
    let width = redis_sub_bucket_nanos(1);
    let bucket = RedisRateLimitClient::sub_bucket_at(Duration::from_millis(600_000), 1);
    let oldest_start = (bucket.index - REDIS_WINDOW_TRAILING_SUB_BUCKETS as u64) as u128 * width;
    let covered = Duration::from_millis(600_000).as_nanos() - oldest_start;
    assert!(covered >= 1_000_000_000 + width);
    assert!(covered <= 1_000_000_000 + 2 * width);

    // Measured from the instant the SERVER executes the decision, one more
    // sub-bucket: settlement admits a reader that selected `s - 1`, so its
    // execution instant can sit a whole bucket past the one its ladder was
    // built around. That is the `W + 3 * (W / K)` the documented over-count
    // bound states, and `placement_lag_widens_the_counted_history_to_three_sub_buckets`
    // is what pins the request counts it implies.
    let latest_execution = (bucket.index as u128 + 2) * width - 1;
    let covered_from_execution = latest_execution - oldest_start;
    assert!(covered_from_execution > 1_000_000_000 + 2 * width);
    assert!(covered_from_execution <= 1_000_000_000 + 3 * width);
}

/// The honest steady-state cost of counting the oldest sub-bucket in full, for
/// a HOMOGENEOUS stream — every request carrying the same placement lag.
///
/// Any bucketed counter that counts its oldest bucket at face value covers MORE
/// than the exact trailing window, so a client sending at EXACTLY its
/// configured rate is throttled. Measured between requests that all place their
/// charge the same way, the extra history is at most two sub-buckets — up to
/// `ceil(2 * limit / K)` requests — so the admitted fraction is
/// `limit / (limit + ceil(2 * limit / K))`. For `K = 16` that is one half at
/// `limit = 1`, two thirds at `limit = 2`, and eight ninths at `limit = 8`.
///
/// This is the BETTER case, not the contract. The documented bound is
/// `limit / (limit + ceil(3 * limit / K))`, because a reader whose own
/// transaction straddles a sub-bucket boundary reads a ladder built one bucket
/// before the bucket it executes in while the charges it counts did not —
/// `placement_lag_widens_the_counted_history_to_three_sub_buckets` is what pins
/// that. A uniform latency does NOT widen it, which is why the sweep below
/// repeats every case with a straddling one and gets the same answer: the key
/// is the selection bucket either way, so shifting every request equally shifts
/// nothing.
///
/// Every arrival below lands exactly on a sub-bucket edge, which is the worst
/// phase for the oldest bucket and the one a "roughly" argument would skip.
#[test]
fn steady_traffic_pays_the_documented_sub_bucket_quantisation() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_WINDOW_SUB_BUCKETS;

    const NANOS_PER_SECOND: u64 = 1_000_000_000;
    let sub_bucket_nanos = NANOS_PER_SECOND / REDIS_WINDOW_SUB_BUCKETS as u64;

    // (limit, requests offered, admissions the ladder actually grants)
    //
    // The start is epoch second 100, which is sub-bucket 1600 exactly, so the
    // first arrival of every case sits on a bucket edge. Counts are the closed
    // form of the steady-state cycle, verified below against the fraction the
    // doc comment and `docs/plugins.md` promise.
    let cases: [(u64, u64, u64); 3] = [
        // 1/s: admit, refuse, admit, refuse … — exactly half.
        (1, 20, 10),
        // 2/s: admit, admit, refuse … — exactly two thirds.
        (2, 21, 14),
        // 8/s: eight admissions then one refusal — exactly eight ninths.
        (8, 36, 32),
    ];

    // A latency of zero, and one that pushes every execution into the sub-bucket
    // AFTER the one it selected — the widest placement lag settlement admits.
    // Both are homogeneous, so both must produce the same figures: the key is
    // the selection bucket either way, and shifting every request equally
    // shifts nothing.
    let latencies = [Duration::ZERO, Duration::from_nanos(sub_bucket_nanos)];

    for (limit, offered, expected_admitted) in cases {
        // Exactly the configured rate: `limit` arrivals per second, evenly
        // spaced, every one on a sub-bucket edge.
        let spacing_nanos = NANOS_PER_SECOND / limit;
        for latency in latencies {
            let mut buckets = std::collections::HashMap::new();
            let mut admitted = 0_u64;
            for attempt in 0..offered {
                let at = Duration::from_nanos(100 * NANOS_PER_SECOND + attempt * spacing_nanos);
                if model_sub_bucket_admits(&mut buckets, at, latency, 1, limit) {
                    admitted += 1;
                }
            }
            assert_eq!(
                admitted, expected_admitted,
                "limit {limit} at latency {latency:?}: {admitted}/{offered} admitted"
            );

            // The closed form for a homogeneous stream: at most
            // `ceil(2 * limit / K)` requests of extra history are counted.
            let excess = (limit * 2).div_ceil(REDIS_WINDOW_SUB_BUCKETS as u64);
            let predicted = limit as f64 / (limit + excess) as f64;
            let measured = admitted as f64 / offered as f64;
            assert!(
                (measured - predicted).abs() < 0.02,
                "limit {limit} at latency {latency:?}: measured {measured} vs homogeneous \
                 {predicted}"
            );
            // And never below the documented bound, which allows one more
            // sub-bucket of history than a homogeneous stream ever counts.
            let bound_excess = (limit * 3).div_ceil(REDIS_WINDOW_SUB_BUCKETS as u64);
            let bound = limit as f64 / (limit + bound_excess) as f64;
            assert!(
                measured + 0.02 >= bound,
                "limit {limit} at latency {latency:?}: measured {measured} below the \
                 documented bound {bound}"
            );
            // The quota still binds: a client at exactly its configured rate is
            // throttled, which is the whole point of stating the figure.
            assert!(
                admitted < offered,
                "limit {limit} at latency {latency:?}: the quota must still bind \
                 ({admitted}/{offered})"
            );
        }
    }

    // A sanity anchor on the sub-bucket width the spacing above rests on.
    assert_eq!(sub_bucket_nanos, 62_500_000);
}

/// Review finding (MINOR 4): the ladder's real over-count is THREE sub-buckets,
/// not two, once the reader's own placement lag is modelled.
///
/// A charge is keyed at the sub-bucket it SELECTED; settlement deliberately
/// admits a transaction the server applies one bucket later. So a reader that
/// executes at server bucket `s` may be reading a ladder built around `s - 1`,
/// starting at `s - K - 2`, while the peers it counts were keyed at the bucket
/// they executed in. Measured execution-to-execution that ladder reaches back
/// `W + 3 * (W / K)` instead of `W + 2 * (W / K)` — up to `ceil(3 * L / K)`
/// requests of extra history rather than `ceil(2 * L / K)`.
///
/// Peers arrive at exactly the configured rate and key their charges at the
/// bucket they executed in. The reader executes at the next instant of that
/// same stream, once with no placement lag and once one whole sub-bucket after
/// its own selection — the widest lag settlement admits. The phase of the whole
/// timeline against the sub-bucket grid is swept, because both figures are the
/// WORST phase and a single alignment would measure the best one.
#[test]
fn placement_lag_widens_the_counted_history_to_three_sub_buckets() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_WINDOW_SUB_BUCKETS;

    const NANOS_PER_SECOND: u64 = 1_000_000_000;
    const PHASE_STEPS: u64 = 64;
    let sub_bucket_nanos = NANOS_PER_SECOND / REDIS_WINDOW_SUB_BUCKETS as u64;
    let base = 100 * NANOS_PER_SECOND;

    for limit in [1_u64, 2, 8, 16, 100] {
        let spacing_nanos = NANOS_PER_SECOND / limit;
        assert_eq!(
            spacing_nanos * limit,
            NANOS_PER_SECOND,
            "limit {limit}: the arrival spacing must divide the window exactly"
        );
        let mut widest_prompt = 0_u64;
        let mut widest_lagging = 0_u64;
        for step in 0..PHASE_STEPS {
            let phase = sub_bucket_nanos * step / PHASE_STEPS;
            let executes_at = Duration::from_nanos(base + phase);
            // Three windows of peers, each keyed at the bucket it executed in,
            // so the reader's ladder is full whatever it reaches back to.
            let mut peers = std::collections::HashMap::new();
            for back in 1..=(limit * 3) {
                let at = Duration::from_nanos(base + phase - back * spacing_nanos);
                let index = RedisRateLimitClient::sub_bucket_at(at, 1).index;
                *peers.entry(index).or_insert(0) += 1;
            }

            let counted_by = |selected_at: Duration, lag: Duration| {
                model_sub_bucket_decision(&mut peers.clone(), selected_at, lag, 1, limit)
                    .counted
                    .expect("a charge inside the settlement band always settles")
            };
            // One whole sub-bucket of placement lag: the reader selected at
            // `s - 1` and the server applied the transaction at `s`, which is
            // exactly the straddle `sub_bucket_charge_is_settled` admits.
            let lag = Duration::from_nanos(sub_bucket_nanos);
            let lagging_selects_at = executes_at.saturating_sub(lag);
            widest_prompt = widest_prompt.max(counted_by(executes_at, Duration::ZERO));
            widest_lagging = widest_lagging.max(counted_by(lagging_selects_at, lag));
        }

        assert_eq!(
            widest_prompt,
            limit + (limit * 2).div_ceil(REDIS_WINDOW_SUB_BUCKETS as u64),
            "limit {limit}: a reader with no placement lag counts at most TWO \
             sub-buckets of extra history"
        );
        assert_eq!(
            widest_lagging,
            limit + (limit * 3).div_ceil(REDIS_WINDOW_SUB_BUCKETS as u64),
            "limit {limit}: a reader that straddled a sub-bucket boundary counts \
             THREE sub-buckets of extra history — the documented bound"
        );
        assert!(
            widest_lagging > limit,
            "limit {limit}: the quota still binds at exactly the configured rate"
        );
    }
}

/// The reviewer's concrete counterexample to the `W + 2 * (W / K)` history
/// claim, at `1/s`: a peer 1.178 seconds old is still counted.
///
/// A charges key `1600`, executing at `100.003`. B's learned offset is 60ms
/// behind the server, so B selects at local `101.180` — corrected `101.120`,
/// sub-bucket `1617` — and the server applies the transaction at `101.181`,
/// sub-bucket `1618`. That is `b + 1`, so settlement admits it, and B's ladder
/// runs `[1600, 1618]` and includes A.
///
/// A executed 1.178 seconds before B did. The retired claim was that no charge
/// older than `W + 2 * (W / K)` = 1.125s is counted; the real bound is
/// `W + 3 * (W / K)` = 1.1875s, and this sits between the two.
#[test]
fn a_straddling_reader_counts_a_peer_older_than_the_retired_history_claim() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKETS, sub_bucket_charge_is_settled,
    };

    let sub_bucket = Duration::from_nanos(1_000_000_000 / REDIS_WINDOW_SUB_BUCKETS as u64);

    // A: no placement lag, so its key IS the bucket the server executed it in.
    let a_executes = Duration::from_micros(100_003_000);
    let a_bucket = RedisRateLimitClient::sub_bucket_at(a_executes, 1);
    assert_eq!(a_bucket.index, 1_600);
    assert!(sub_bucket_charge_is_settled(a_bucket, a_executes));

    // B: selects on a clock 60ms behind the server, executes 1ms later.
    let b_selects = Duration::from_micros(101_180_000).saturating_sub(Duration::from_millis(60));
    let b_executes = Duration::from_micros(101_181_000);
    let b_bucket = RedisRateLimitClient::sub_bucket_at(b_selects, 1);
    assert_eq!(b_bucket.index, 1_617);
    assert_eq!(
        RedisRateLimitClient::sub_bucket_at(b_executes, 1).index,
        1_618,
        "B's transaction must straddle the boundary for this to be the case under test"
    );
    assert!(
        sub_bucket_charge_is_settled(b_bucket, b_executes),
        "a charge the server applies at b + 1 is exactly what settlement admits"
    );

    // B's ladder starts at `b - K - 1` = 1600, so it counts A. On one timeline
    // the gap between B's selection and the instant the server applied its
    // transaction is 61ms: 1ms of real latency plus the 60ms its learned offset
    // was behind the server.
    let mut server = std::collections::HashMap::from([(a_bucket.index, 1_i64)]);
    let decision =
        model_sub_bucket_decision(&mut server, b_selects, Duration::from_millis(61), 1, 1);
    assert_eq!(
        decision.counted,
        Some(2),
        "B must count A's still-live charge plus its own"
    );
    assert!(
        !decision.admitted,
        "a 1/s quota already spent must refuse B"
    );

    // And the age that makes this the correction rather than a restatement.
    let age = b_executes.saturating_sub(a_executes);
    assert_eq!(age, Duration::from_micros(1_178_000));
    assert!(
        age > Duration::from_secs(1) + 2 * sub_bucket,
        "the retired W + 2*(W/K) claim would have excluded a charge this old: {age:?}"
    );
    assert!(
        age <= Duration::from_secs(1) + 3 * sub_bucket,
        "and the corrected W + 3*(W/K) bound must still contain it: {age:?}"
    );
}

/// The small-quota quantisation is NOT a regression introduced by the
/// sub-bucket ladder: the two-window weighted estimate it replaced refused a
/// `1/s` client every other request as well.
///
/// The weighted estimate still weighs a full `previous` bucket at `0.95` when
/// the current window is 5% elapsed, so `0.95 + 1 > 1` refuses — exactly every
/// other request, indefinitely. The sub-bucket ladder is no worse on the same
/// timeline, and it is what keeps the LARGER limits near their configured rate,
/// where `previous + current` would have halved those too.
#[test]
fn the_retired_weighted_estimate_halved_small_quotas_too() {
    const NANOS_PER_SECOND: u64 = 1_000_000_000;

    // A well-behaved `1/s` poller, deliberately a touch SLOWER than its quota.
    let spacing_nanos = 1_050_000_000_u64;
    let offered = 20_u64;

    let mut weighted = std::collections::HashMap::new();
    let mut weighted_admitted = 0_u64;
    let mut buckets = std::collections::HashMap::new();
    let mut sub_bucket_admitted = 0_u64;
    for attempt in 0..offered {
        let at = Duration::from_nanos(100 * NANOS_PER_SECOND + attempt * spacing_nanos);
        if model_weighted_admits(&mut weighted, at, 1, 1) {
            weighted_admitted += 1;
        }
        if model_sub_bucket_admits(&mut buckets, at, Duration::ZERO, 1, 1) {
            sub_bucket_admitted += 1;
        }
    }

    // Exactly alternating: a refusal rolls its own increment back, so the next
    // request sees `previous = 0` and is admitted, and that admission makes the
    // one after it refuse. `previous` still weighs 0.95 at 5% elapsed, so the
    // odd requests never squeeze in.
    assert_eq!(
        weighted_admitted, 10,
        "the retired weighted estimate admitted only every other request"
    );
    assert!(
        sub_bucket_admitted >= weighted_admitted,
        "the sub-bucket ladder must be no worse than what it replaced at limit 1: \
         {sub_bucket_admitted} vs {weighted_admitted} of {offered}"
    );
    assert!(
        sub_bucket_admitted < offered,
        "the quota must still bind: {sub_bucket_admitted}/{offered}"
    );
}

/// A client three sub-buckets slower than its configured rate is admitted in
/// full, whatever its placement lag.
///
/// This is the other side of the quantisation bound, and it is what makes the
/// cost a *known* one rather than an unbounded throttle. `W + 3 * (W / K)` — one
/// window plus the whole of the extra history a straddling reader can reach —
/// is the spacing `docs/plugins.md` promises, so it must hold at a placement
/// lag of one full sub-bucket as well as at none. A homogeneous stream with no
/// lag clears at the narrower `W + 2 * (W / K)` too, which is the figure that
/// applied before the reader's own lag was accounted for.
#[test]
fn traffic_three_sub_buckets_slower_than_the_configured_rate_is_fully_admitted() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_WINDOW_SUB_BUCKETS;

    const NANOS_PER_SECOND: u64 = 1_000_000_000;
    let sub_bucket_nanos = NANOS_PER_SECOND / REDIS_WINDOW_SUB_BUCKETS as u64;
    // One window plus THREE sub-buckets, divided across the limit.
    let cycle_nanos = NANOS_PER_SECOND + 3 * sub_bucket_nanos;
    // And the narrower cycle, which only the no-lag stream is promised.
    let narrow_cycle_nanos = NANOS_PER_SECOND + 2 * sub_bucket_nanos;
    assert_eq!(narrow_cycle_nanos, NANOS_PER_SECOND + NANOS_PER_SECOND / 8);

    for limit in [1_u64, 2, 8] {
        for (cycle, latency, label) in [
            (cycle_nanos, Duration::ZERO, "W + 3*W/K, no placement lag"),
            (
                cycle_nanos,
                Duration::from_nanos(sub_bucket_nanos),
                "W + 3*W/K, a full sub-bucket of placement lag",
            ),
            (
                narrow_cycle_nanos,
                Duration::ZERO,
                "W + 2*W/K, no placement lag",
            ),
        ] {
            let spacing_nanos = cycle / limit;
            let offered = 40_u64;
            let mut buckets = std::collections::HashMap::new();
            let mut admitted = 0_u64;
            for attempt in 0..offered {
                let at = Duration::from_nanos(100 * NANOS_PER_SECOND + attempt * spacing_nanos);
                if model_sub_bucket_admits(&mut buckets, at, latency, 1, limit) {
                    admitted += 1;
                }
            }
            assert_eq!(
                admitted, offered,
                "limit {limit} ({label}): a client spaced this far apart must never be refused"
            );
        }
    }
}

/// The settlement judgement, against the server clock that `EXEC` returned. It
/// is TWO-SIDED, and both ends are load-bearing.
///
/// Late (`> b + 1`) means a peer may have charged a bucket this ladder neither
/// read nor charged. EARLY (`< b`) means the charge was placed in the FUTURE,
/// where no peer's trailing window reaches it — the case a gateway whose clock
/// runs ahead of Redis produces, and the one that let an unsampled gateway at
/// `700s` charge bucket `11200` while the server ordered everything at `1600`.
///
/// Together the two ends pin every retained charge's key to
/// `{exec_bucket - 1, exec_bucket}`, which is exactly the span the ladder's
/// extra old counter covers.
#[test]
fn a_charge_is_settled_only_within_one_sub_bucket_of_its_selection() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        RedisRateLimitClient, sub_bucket_charge_is_settled,
    };

    let ms = Duration::from_millis;
    let selected = RedisRateLimitClient::sub_bucket_at(ms(100_000), 1);
    assert_eq!(selected.index, 1_600);

    // Same bucket, and the next one: the ladder read `1601`, so a peer that
    // charged there is already counted.
    assert!(sub_bucket_charge_is_settled(selected, ms(100_062)));
    assert!(sub_bucket_charge_is_settled(selected, ms(100_124)));
    // Two buckets on: `1602` was neither read nor charged, so a peer there is
    // invisible and the decision cannot be published.
    assert!(!sub_bucket_charge_is_settled(selected, ms(100_125)));
    assert!(!sub_bucket_charge_is_settled(selected, ms(100_600)));

    // A charge the server applied BEFORE the bucket it was keyed to sits in the
    // future, where no peer's trailing window reaches it. Accepting it was the
    // hole that let a gateway whose clock ran ahead of Redis charge an
    // unreachable ladder and then admit again on the corrected one.
    assert!(!sub_bucket_charge_is_settled(selected, ms(99_999)));
    assert!(!sub_bucket_charge_is_settled(selected, ms(99_000)));

    // One bucket back is a whole sub-bucket of placement error, so it is
    // refused just like one bucket too far forward: the band is exactly
    // `[b, b + 1]`.
    let ahead = RedisRateLimitClient::sub_bucket_at(ms(700_000), 1);
    assert_eq!(ahead.index, 11_200);
    assert!(!sub_bucket_charge_is_settled(ahead, ms(100_000)));
    assert!(sub_bucket_charge_is_settled(ahead, ms(700_000)));
}

/// The admission decision reads the bucket clock only through the client's
/// server-clock correction, and settles on the instant `EXEC` returned.
///
/// The bare local clock must not appear here at all: a raw `SystemTime` sample
/// is what let two gateways disagree about which sub-bucket "now" is, and a
/// local post-`EXEC` sample is what conflated harmless reply latency with a
/// genuinely late execution.
#[test]
fn a_quota_decision_reads_the_bucket_clock_only_through_the_server_correction() {
    let source = include_str!("../../../src/plugins/utils/rate_limit.rs");
    let body = source
        .split("async fn check_http_windows_redis(")
        .nth(1)
        .expect("check_http_windows_redis must exist");
    let body = body
        .split("\n#[cfg(test)]")
        .next()
        .expect("function body ends before the test-only items");

    assert_eq!(
        body.matches("redis_epoch_now()").count(),
        0,
        "admission must never read this process's clock directly; every instant \
         comes from the client's server-clock correction"
    );
    // Per-window live sampling is what the shared sample replaced.
    assert!(
        !body.contains("RedisRateLimitClient::sub_bucket("),
        "every window must derive its bucket from the shared sample"
    );
    let seed = body
        .find("redis.ensure_clock_seeded().await;")
        .expect("the first selection must come after the connection probe");
    let select = body
        .find("let mut sampled_at = redis.server_clock().now();")
        .expect("the first ladder must be built on the corrected server clock");
    assert!(
        seed < select,
        "bucket selection otherwise precedes connection acquisition, so the FIRST \
         request of a client's life would select on the raw local clock"
    );
    assert!(
        body.contains("RedisRateLimitClient::sub_bucket_at(sampled_at, window_seconds)"),
        "the ladder must be derived from the captured instant"
    );
    assert!(
        body.contains("charged.settled_at()"),
        "settlement must use the server clock the charge transaction returned"
    );
    assert!(
        body.contains("sub_bucket_charge_is_settled(charge.bucket(), settled_at)"),
        "the settlement check must use the shared staleness helper"
    );
    assert!(
        body.contains("sampled_at = settled_at;"),
        "the rebuild must reuse the server instant that proved the rollover"
    );
    assert!(
        body.contains("compensation.confirmed().await"),
        "the rebuild must wait for its own hand-back to land"
    );
}

/// Every production token-accounting path reasons in the ONE shared weighted
/// formula, so a change to it cannot leave one caller behind with a green test.
///
/// The `ai_rate_limiter` `Check`/`Reserve`/`AdjustUsage` arms and the
/// `ws_rate_limiting` frame budget each used to spell the estimate out inline;
/// the retained `FixedWindow` decay coverage then proved nothing about them.
#[test]
fn token_accounting_paths_share_the_one_weighted_formula() {
    let source = include_str!("../../../src/plugins/utils/rate_limit.rs");

    assert!(
        source.contains("pub(crate) fn weighted_window_count("),
        "the weighted estimate must live in one shared helper"
    );
    // Three ai_rate_limiter arms, the ws_rate_limiting frame budget, and
    // FixedWindow::weighted_count.
    assert_eq!(
        source.matches("weighted_window_count(").count(),
        6,
        "every weighted caller must route through the shared helper"
    );
    assert!(
        !source.contains("as f64 * (1.0 - elapsed_fraction)"),
        "no caller may keep its own inline copy of the weighted formula"
    );
}

#[test]
fn shared_consumers_use_same_window_progress_helper() {
    // rate_limiting, GraphQL type/named-operation limits, and grpc_method_router
    // per-method limits all reach check_http_windows_redis → sub_bucket, and the
    // token-accounting paths (`ai_rate_limiter`, `ws_rate_limiting`) all reach
    // window_progress. Prove the shared helpers (not per-plugin copies) are what
    // the test support and live clock paths expose.
    use ferrum_edge::_test_support::{redis_window_progress, redis_window_progress_at};
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_SUB_BUCKETS, RedisRateLimitClient,
    };

    let at = redis_window_progress_at(Duration::from_millis(1_250), 1);
    let direct = RedisRateLimitClient::window_progress_at(Duration::from_millis(1_250), 1);
    assert_eq!(at, direct);
    assert!((at.elapsed_fraction - 0.25).abs() < 1e-12);

    // The quota ladder is derived from the same wall clock. Sample the window
    // first: a sub-bucket taken no earlier than it can never precede that
    // window's first sub-bucket.
    let live = redis_window_progress(1);
    assert!(live.elapsed_fraction >= 0.0 && live.elapsed_fraction < 1.0);
    let live_bucket = RedisRateLimitClient::sub_bucket(1);
    assert_eq!(live_bucket.window_seconds, 1);
    assert!(live_bucket.index >= live.index * REDIS_WINDOW_SUB_BUCKETS as u64);
}

// ── Reordered / stalled quota transactions (review of PR #5584) ───────────
//
// Bucket selection samples the clock BEFORE the pooled connection is acquired,
// so a charge always executes slightly after it was built. Two properties have
// to hold under that:
//
// 1. Two requests on either side of a sub-bucket boundary must not both be
//    admitted against a one-request quota, whichever transaction reaches the
//    server first. The forward `GET` is what makes that order-independent.
// 2. A stall longer than a whole sub-bucket is not covered by the forward
//    `GET`, so the caller must hand its charge back and rebuild once, and fail
//    closed if that rebuild rolls over as well.
//
// Both are exercised against a fake RESP server that keeps a REAL keyspace, so
// `GET`/`INCR`/`DECR` answer with the values the ladder actually wrote.

/// Parse one complete RESP command array out of `buf`, returning every
/// argument.
///
/// Framing is exact for the same reason [`parse_resp_command`] is: a server
/// that guesses at chunk boundaries answers a split or coalesced write with the
/// wrong number of replies and drives the client's multiplexed connection into
/// an accounting underflow instead of the behavior under test.
fn parse_resp_command_args(buf: &[u8]) -> Option<(Vec<String>, usize)> {
    fn read_line(buf: &[u8], from: usize) -> Option<(&[u8], usize)> {
        let rest = buf.get(from..)?;
        let idx = rest.windows(2).position(|w| w == b"\r\n")?;
        Some((&rest[..idx], from + idx + 2))
    }

    if *buf.first()? != b'*' {
        return None;
    }
    let (count_line, mut cursor) = read_line(buf, 1)?;
    let argc: usize = std::str::from_utf8(count_line).ok()?.parse().ok()?;
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if *buf.get(cursor)? != b'$' {
            return None;
        }
        let (len_line, after_len) = read_line(buf, cursor + 1)?;
        let len: usize = std::str::from_utf8(len_line).ok()?.parse().ok()?;
        let end = after_len.checked_add(len)?;
        let payload = buf.get(after_len..end)?;
        if buf.get(end..end + 2)? != b"\r\n" {
            return None;
        }
        args.push(String::from_utf8_lossy(payload).to_string());
        cursor = end + 2;
    }
    Some((args, cursor))
}

/// Where a held `EXEC` sleeps relative to APPLYING its commands.
///
/// The distinction is the whole point of judging settlement on the server's
/// own clock: only one of these two is a hazard.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HoldPhase {
    /// Sleep BEFORE applying: the transaction genuinely executes late, so its
    /// own `TIME` reports the late instant and a peer may have charged a bucket
    /// this ladder never read. This is the real hazard.
    BeforeApply,
    /// Sleep AFTER applying: the transaction executed on time and only its
    /// REPLY is late. Harmless — a peer charging afterwards reads this
    /// request's own increment — but a local post-`EXEC` sample cannot tell the
    /// two apart and would roll the ladder over for nothing.
    AfterApply,
}

/// How the fake server answers `TIME`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ServerTimeMode {
    /// The server's real clock, which is also the clock the client's local
    /// samples read, so the learned offset settles near zero.
    RealClock,
    /// A server clock genuinely ahead of this process's, so a client that used
    /// its own clock would pick different sub-buckets than the server orders
    /// charges on.
    Ahead(Duration),
    /// A server clock genuinely BEHIND this process's: the gateway is fast
    /// relative to Redis, so an uncorrected selection lands in the future,
    /// where no peer's trailing window reaches it.
    Behind(Duration),
    /// A restrictive ACL: `TIME` is refused. A request-quota client's connection
    /// cannot be screened, so the store is unavailable and
    /// `redis_failure_policy` governs. A client that reads no clock never sends
    /// the command and is unaffected.
    Denied,
    /// A RESP-compatible server that does not implement `TIME` at all. Like
    /// `Denied`, a permanent statement about the endpoint — and the same
    /// outcome, because the bucket clock is not optional.
    UnknownCommand,
    /// The standalone probe is ALLOWED and answers something that is not a
    /// clock. That says nothing about the ACL, so the connection must be
    /// treated as unscreened rather than silently downgraded.
    MalformedProbe,
    /// The standalone probe never answers inside the screened per-command
    /// deadline.
    ProbeTimeout,
    /// The server closes the connection when the standalone probe arrives.
    ProbeTransportError,
    /// The standalone probe answers a real clock, but the `TIME` queued inside
    /// a transaction answers something that is not one. The client must treat
    /// that as an unusable endpoint rather than silently reinstating its own
    /// clock on an endpoint that claimed to support the server's.
    MalformedInTransaction,
}

/// Knobs for one fake server. Defaults answer everything immediately from the
/// real clock.
#[derive(Clone, Copy)]
struct KeyspaceServerOptions {
    charge_delay: Duration,
    delayed_charges: usize,
    hold_phase: HoldPhase,
    compensation_delay: Duration,
    delayed_compensations: usize,
    time_mode: ServerTimeMode,
    /// Append one bogus element to every `EXEC` array, so the client's
    /// reply-length validation sees a shape it cannot pair with its windows.
    extra_exec_element: bool,
}

impl Default for KeyspaceServerOptions {
    fn default() -> Self {
        Self {
            charge_delay: Duration::ZERO,
            delayed_charges: 0,
            hold_phase: HoldPhase::BeforeApply,
            compensation_delay: Duration::ZERO,
            delayed_compensations: 0,
            time_mode: ServerTimeMode::RealClock,
            extra_exec_element: false,
        }
    }
}

/// What one `EXEC` does about timing: how long it is held, and on which side of
/// applying its commands.
struct ExecSchedule {
    hold: Duration,
    phase: HoldPhase,
}

/// Whether an `EXEC` batch queued a command with this name.
fn batch_contains(batch: &[Vec<String>], command: &str) -> bool {
    batch
        .iter()
        .filter_map(|queued| queued.first())
        .any(|name| name.eq_ignore_ascii_case(command))
}

/// Shared keyspace and counters of the fake server, cloned into each
/// connection task.
#[derive(Clone)]
struct KeyspaceState {
    keys: Arc<std::sync::Mutex<std::collections::HashMap<String, i64>>>,
    incrs: Arc<AtomicUsize>,
    decrs: Arc<AtomicUsize>,
    charges: Arc<AtomicUsize>,
    compensations: Arc<AtomicUsize>,
    /// Applied mutations in the order the keyspace saw them. Recorded under the
    /// keyspace lock, so it is the real serialization order across connections
    /// and not a dispatch order — which is what an ordering assertion needs.
    ops: Arc<std::sync::Mutex<Vec<&'static str>>>,
    /// Standalone `TIME` commands this server answered — the connection-screening
    /// probe, counted apart from the `TIME` that rides inside a charge
    /// transaction. Zero proves a client never asked for the server clock.
    clock_probes: Arc<AtomicUsize>,
    /// The fixture's `TIME` behaviour, settable while the server is running so
    /// a test can revoke or restore the ACL under a LIVE client — which is the
    /// only way to exercise a clock-mode transition rather than a startup
    /// verdict.
    time_mode: Arc<std::sync::Mutex<ServerTimeMode>>,
    options: KeyspaceServerOptions,
}

impl KeyspaceState {
    /// The fixture's current `TIME` behaviour.
    fn time_mode(&self) -> ServerTimeMode {
        *self.time_mode.lock().expect("time mode mutex")
    }

    /// This server's own clock, as `TIME` would report it.
    fn server_now(&self) -> Duration {
        let real = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        match self.time_mode() {
            ServerTimeMode::Ahead(shift) => real.saturating_add(shift),
            ServerTimeMode::Behind(shift) => real.saturating_sub(shift),
            _ => real,
        }
    }

    /// Whether a `TIME` queued inside a transaction answers a non-clock.
    fn breaks_transaction_time(&self) -> bool {
        self.time_mode() == ServerTimeMode::MalformedInTransaction
    }

    /// Apply ONE command to the fake keyspace and return its RESP reply.
    fn apply(&self, args: &[String], in_transaction: bool) -> Vec<u8> {
        let name = args
            .first()
            .map(|arg| arg.to_uppercase())
            .unwrap_or_default();
        // Read the clock before taking the keyspace lock; `TIME` touches no key.
        if name == "TIME" {
            if in_transaction && self.breaks_transaction_time() {
                return b"+OK\r\n".to_vec();
            }
            if !in_transaction {
                self.clock_probes.fetch_add(1, Ordering::Relaxed);
            }
            return match self.time_mode() {
                ServerTimeMode::Denied => TIME_DENIED_REPLY.to_vec(),
                ServerTimeMode::UnknownCommand => TIME_UNKNOWN_COMMAND_REPLY.to_vec(),
                ServerTimeMode::MalformedProbe => b"+OK\r\n".to_vec(),
                _ => encode_server_time(self.server_now()),
            };
        }
        let key = args.get(1).cloned().unwrap_or_default();
        let mut store = self.keys.lock().expect("keyspace mutex");
        match name.as_str() {
            "GET" => match store.get(&key) {
                Some(value) => {
                    let rendered = value.to_string();
                    format!("${}\r\n{rendered}\r\n", rendered.len()).into_bytes()
                }
                None => b"$-1\r\n".to_vec(),
            },
            "INCR" => {
                self.incrs.fetch_add(1, Ordering::Relaxed);
                self.ops.lock().expect("op log mutex").push("INCR");
                let slot = store.entry(key).or_insert(0);
                *slot += 1;
                let value = *slot;
                format!(":{value}\r\n").into_bytes()
            }
            "DECR" => {
                self.decrs.fetch_add(1, Ordering::Relaxed);
                self.ops.lock().expect("op log mutex").push("DECR");
                let slot = store.entry(key).or_insert(0);
                *slot -= 1;
                let value = *slot;
                format!(":{value}\r\n").into_bytes()
            }
            "EXPIRE" => b":1\r\n".to_vec(),
            _ => b"+OK\r\n".to_vec(),
        }
    }

    /// Classify one `EXEC`'s queued batch and consume its place in the
    /// fixture's schedule. Called exactly once per transaction.
    fn schedule_for(&self, batch: &[Vec<String>]) -> ExecSchedule {
        if batch_contains(batch, "INCR") {
            let index = self.charges.fetch_add(1, Ordering::Relaxed);
            return ExecSchedule {
                hold: if index < self.options.delayed_charges {
                    self.options.charge_delay
                } else {
                    Duration::ZERO
                },
                phase: self.options.hold_phase,
            };
        }
        if batch_contains(batch, "DECR") {
            let index = self.compensations.fetch_add(1, Ordering::Relaxed);
            return ExecSchedule {
                // A held compensation is held before it applies: the point is
                // that the `DECR` has genuinely not landed yet.
                hold: if index < self.options.delayed_compensations {
                    self.options.compensation_delay
                } else {
                    Duration::ZERO
                },
                phase: HoldPhase::BeforeApply,
            };
        }
        ExecSchedule {
            hold: Duration::ZERO,
            phase: HoldPhase::BeforeApply,
        }
    }

    /// Handle one received command and append its reply. `false` closes the
    /// connection instead of answering, which is how the fixture produces a
    /// transport failure on a specific command.
    async fn handle(
        &self,
        queued: &mut Option<Vec<Vec<String>>>,
        args: Vec<String>,
        reply: &mut Vec<u8>,
    ) -> bool {
        let name = args
            .first()
            .map(|arg| arg.to_uppercase())
            .unwrap_or_default();
        // The standalone `TIME` probe is the only command whose failure mode is
        // about the TRANSPORT rather than the reply, so it is handled here (in
        // async context) rather than in the synchronous `apply`.
        if name == "TIME" && queued.is_none() {
            match self.time_mode() {
                ServerTimeMode::ProbeTimeout => {
                    // Far past the screened per-command deadline.
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    reply.extend_from_slice(&self.apply(&args, false));
                }
                ServerTimeMode::ProbeTransportError => return false,
                _ => reply.extend_from_slice(&self.apply(&args, false)),
            }
            return true;
        }
        match name.as_str() {
            "INFO" => {
                let text = "# Cluster\r\ncluster_enabled:0\r\n";
                let bulk = format!("${}\r\n{text}\r\n", text.len());
                reply.extend_from_slice(bulk.as_bytes());
            }
            "MULTI" => {
                *queued = Some(Vec::new());
                reply.extend_from_slice(b"+OK\r\n");
            }
            "EXEC" => {
                let batch = queued.take().unwrap_or_default();
                let schedule = self.schedule_for(&batch);
                if !schedule.hold.is_zero() && schedule.phase == HoldPhase::BeforeApply {
                    tokio::time::sleep(schedule.hold).await;
                }
                let extra = usize::from(self.options.extra_exec_element);
                let values = batch.len() + extra;
                let mut body = format!("*{values}\r\n").into_bytes();
                for command in &batch {
                    body.extend_from_slice(&self.apply(command, true));
                }
                if self.options.extra_exec_element {
                    body.extend_from_slice(b":1\r\n");
                }
                if !schedule.hold.is_zero() && schedule.phase == HoldPhase::AfterApply {
                    tokio::time::sleep(schedule.hold).await;
                }
                reply.extend_from_slice(&body);
            }
            _ => match queued.as_mut() {
                Some(batch) => {
                    batch.push(args);
                    reply.extend_from_slice(b"+QUEUED\r\n");
                }
                None => reply.extend_from_slice(&self.apply(&args, false)),
            },
        }
        true
    }
}

struct KeyspaceServer {
    port: u16,
    shutdown: oneshot::Sender<()>,
    state: KeyspaceState,
}

impl KeyspaceServer {
    /// Change how the server answers `TIME` while a client is already running,
    /// so a test can revoke or restore the ACL mid-life.
    fn set_time_mode(&self, mode: ServerTimeMode) {
        *self.state.time_mode.lock().expect("time mode mutex") = mode;
    }

    fn counter(&self, key: &str) -> i64 {
        self.state
            .keys
            .lock()
            .expect("keyspace mutex")
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    fn incrs(&self) -> usize {
        self.state.incrs.load(Ordering::Relaxed)
    }

    fn decrs(&self) -> usize {
        self.state.decrs.load(Ordering::Relaxed)
    }

    /// Standalone `TIME` commands answered: the connection-screening probe.
    fn clock_probes(&self) -> usize {
        self.state.clock_probes.load(Ordering::Relaxed)
    }

    /// Every key the fake keyspace holds.
    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .state
            .keys
            .lock()
            .expect("keyspace mutex")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    /// Applied `INCR`/`DECR` mutations, in keyspace order.
    fn ops(&self) -> Vec<&'static str> {
        self.state.ops.lock().expect("op log mutex").clone()
    }

    fn charged_total(&self) -> i64 {
        self.state
            .keys
            .lock()
            .expect("keyspace mutex")
            .values()
            .copied()
            .sum()
    }
}

/// Every sub-bucket the fake keyspace holds, as `(sub_index, counter)`, oldest
/// first.
///
/// Placement assertions read this rather than recomputing the expected index,
/// so a sub-bucket boundary crossing between the traffic and the assertion
/// cannot decide the result.
fn charged_sub_buckets(server: &KeyspaceServer) -> Vec<(u64, i64)> {
    let mut charged: Vec<(u64, i64)> = server
        .keys()
        .into_iter()
        .map(|key| {
            let index: u64 = key
                .rsplit(':')
                .next()
                .expect("the key names its sub-bucket last")
                .parse()
                .expect("sub-bucket index");
            (index, server.counter(&key))
        })
        .collect();
    charged.sort_by_key(|(index, _)| *index);
    charged
}

/// Minimal RESP server with a REAL integer keyspace and working `MULTI`/`EXEC`.
///
/// `GET` answers the stored value (or nil), `INCR`/`DECR` mutate and answer the
/// new value, `EXPIRE` answers `:1`, `TIME` answers this fixture's server clock
/// (or `NOPERM` under [`ServerTimeMode::Denied`]), `INFO` reports a non-Cluster
/// server, and anything else answers `+OK`. Inside a transaction every queued
/// command answers `+QUEUED` and `EXEC` answers the array of their results,
/// which is the shape `redis::pipe().atomic()` decodes.
///
/// `delayed_charges` holds the FIRST `delayed_charges` CHARGE transactions for
/// `charge_delay`, and `delayed_compensations` does the same for hand-backs.
/// `hold_phase` decides whether a held charge sleeps before applying (a real
/// execution stall, so its own `TIME` reports the late instant) or after (only
/// the reply is late). All counts are per server, not per connection.
async fn spawn_keyspace_redis_server(options: KeyspaceServerOptions) -> KeyspaceServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let state = KeyspaceState {
        keys: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        incrs: Arc::new(AtomicUsize::new(0)),
        decrs: Arc::new(AtomicUsize::new(0)),
        charges: Arc::new(AtomicUsize::new(0)),
        compensations: Arc::new(AtomicUsize::new(0)),
        ops: Arc::new(std::sync::Mutex::new(Vec::new())),
        clock_probes: Arc::new(AtomicUsize::new(0)),
        time_mode: Arc::new(std::sync::Mutex::new(options.time_mode)),
        options,
    };
    let accept_state = state.clone();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break; };
                    tokio::spawn(serve_keyspace_connection(stream, accept_state.clone()));
                }
            }
        }
    });

    KeyspaceServer {
        port,
        shutdown: shutdown_tx,
        state,
    }
}

/// One connection's read/reply loop: exactly one reply per fully received
/// command, so the client's in-flight accounting always matches.
async fn serve_keyspace_connection(mut stream: tokio::net::TcpStream, state: KeyspaceState) {
    let mut buf = vec![0u8; 16 * 1024];
    let mut pending: Vec<u8> = Vec::new();
    // Commands queued by the current MULTI, if any.
    let mut queued: Option<Vec<Vec<String>>> = None;
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        let mut reply = Vec::new();
        let mut keep_open = true;
        while let Some((args, consumed)) = parse_resp_command_args(&pending) {
            pending.drain(..consumed);
            if !state.handle(&mut queued, args, &mut reply).await {
                keep_open = false;
                break;
            }
        }
        if !keep_open {
            let _ = stream.write_all(&reply).await;
            return;
        }
        if reply.is_empty() {
            continue;
        }
        if stream.write_all(&reply).await.is_err() {
            break;
        }
    }
}

fn keyspace_config(port: u16) -> RedisConfig {
    let url = format!("redis://127.0.0.1:{port}/0");
    let mut config = make_config(&url, false);
    config.connect_timeout_seconds = 5;
    // Long enough that no background recovery dial happens during a test.
    config.health_check_interval_seconds = 3600;
    // Four pooled slots so a held charge cannot serialize an unrelated
    // transaction behind it on one socket; the timing under test is the
    // client's, not the fake server's read loop.
    config.pool_size = 4;
    config
}

fn keyspace_client(port: u16) -> RedisRateLimitClient {
    redis_rate_limit_client_for_test(keyspace_config(port))
}

/// Two requests that select adjacent sub-buckets must not both be admitted
/// against a one-request quota, even when the NEWER ladder executes first.
///
/// Review finding (MAJOR 2): A samples `100.124s` and selects bucket `1601`,
/// then stalls behind connection acquisition; B samples `100.126s`, selects
/// `1602`, and executes first. Both timestamps are inside one trailing second.
/// With a trailing-only ladder A would read `1584..=1601`, never see B's charge
/// in `1602`, and be admitted alongside it. Reading `1602` as well makes
/// whichever transaction lands SECOND observe the other.
#[tokio::test]
async fn a_reordered_transaction_across_a_sub_bucket_boundary_cannot_double_admit() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_TRAILING_SUB_BUCKETS, RedisWindowCharges,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions::default()).await;
    let client = keyspace_client(server.port);

    let earlier = RedisRateLimitClient::sub_bucket_at(Duration::from_micros(100_124_000), 1);
    let later = RedisRateLimitClient::sub_bucket_at(Duration::from_micros(100_126_000), 1);
    assert_eq!(earlier.index, 1_601);
    assert_eq!(
        later.index,
        earlier.index + 1,
        "the two samples must straddle exactly one sub-bucket boundary"
    );

    let mut stalled = RedisWindowCharges::default();
    assert!(stalled.push(client.window_charge("ip:127.0.0.1", earlier, 3)));
    let mut newer = RedisWindowCharges::default();
    assert!(newer.push(client.window_charge("ip:127.0.0.1", later, 3)));
    let stalled_ladder: Vec<String> = stalled.as_slice()[0]
        .trailing_keys()
        .map(str::to_string)
        .collect();
    let stalled_charged = stalled.as_slice()[0].charged_key().to_string();

    // The NEWER ladder executes FIRST — the reordering the finding describes.
    let newer_counts = client
        .charge_rate_limit_windows(newer.as_slice())
        .await
        .expect("the newer transaction must execute");
    let stalled_counts = client
        .charge_rate_limit_windows(stalled.as_slice())
        .await
        .expect("the stalled transaction must execute");

    let limit = 1_u64;
    let admitted = [newer_counts, stalled_counts]
        .iter()
        .filter(|counts| counts.as_slice()[0] <= limit)
        .count();
    assert_eq!(
        admitted, 1,
        "exactly one of two requests inside one trailing second may be admitted; \
         newer={newer_counts:?} stalled={stalled_counts:?}"
    );
    assert_eq!(
        newer_counts.as_slice()[0],
        1,
        "the transaction that landed first sees only itself"
    );
    assert_eq!(
        stalled_counts.as_slice()[0],
        2,
        "the transaction that landed second must see the peer one bucket ahead"
    );

    // What the trailing-only ladder would have read: its own increment and
    // nothing else, so BOTH would have been admitted. This is the arithmetic
    // the forward `GET` changes, read straight off the fake keyspace.
    let trailing_only: i64 = stalled_ladder
        .iter()
        .map(|key| server.counter(key))
        .sum::<i64>()
        + server.counter(&stalled_charged);
    assert_eq!(
        trailing_only, 1,
        "without the forward counter the stalled ladder sums to 1 and over-admits"
    );
    assert_eq!(stalled_ladder.len(), REDIS_WINDOW_TRAILING_SUB_BUCKETS);

    let _ = server.shutdown.send(());
}

/// A charge whose sub-bucket rolled past `b + 1` before the reply arrived is
/// handed back and rebuilt exactly once.
///
/// Beyond one sub-bucket the forward `GET` no longer covers the drift: a peer
/// may have charged a bucket the ladder neither read nor charged. The decision
/// is therefore not published — the charge is compensated and the ladder is
/// rebuilt from the server instant that proved the rollover, for one more
/// transaction.
#[tokio::test]
async fn a_charge_that_rolls_past_its_sub_bucket_is_handed_back_and_rebuilt_once() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    // A one-second window has 62.5ms sub-buckets, so stalling the first
    // transaction for 250ms before it EXECUTES guarantees the server applies it
    // well past `b + 1` and reports that instant in its own `TIME`. The hold
    // stays inside the 500ms screened per-command response deadline.
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(250),
        delayed_charges: 1,
        hold_phase: HoldPhase::BeforeApply,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let outcome = algorithm
        .check_redis(&client, "ip:127.0.0.1", &op)
        .await
        .expect("the rebuilt pass must produce a decision");
    assert!(
        outcome.allowed,
        "an empty quota admits once the rebuilt ladder lands"
    );

    // Two charges: the rolled-over pass and the rebuild. One compensation: the
    // rolled-over pass handing its own charge back. The hand-back is detached,
    // so settle it before reading the counters.
    for _ in 0..6_000 {
        if client.pending_compensations_for_test() == 0 && server.decrs() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        server.incrs(),
        2,
        "the rolled-over pass and the rebuild are two charges, and no more"
    );
    assert_eq!(
        server.decrs(),
        1,
        "the abandoned pass must hand its own charge back"
    );

    let _ = server.shutdown.send(());
}

/// A second consecutive rollover fails closed rather than publishing a decision
/// derived from a ladder that provably missed part of its own window.
#[tokio::test]
async fn a_second_sub_bucket_rollover_fails_closed() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    // Every CHARGE stalls 250ms before it executes, so the rebuild rolls over
    // as well.
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(250),
        delayed_charges: usize::MAX,
        hold_phase: HoldPhase::BeforeApply,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        result.is_err(),
        "two consecutive rollovers must fail closed, not admit: {result:?}"
    );

    // Both passes handed their own charge back, so nothing is stranded.
    for _ in 0..6_000 {
        if client.pending_compensations_for_test() == 0 && server.decrs() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        server.incrs(),
        2,
        "the bounded rebuild must stop at two transactions"
    );
    assert_eq!(
        server.decrs(),
        2,
        "both abandoned passes must hand their charges back"
    );
    assert_eq!(
        server.charged_total(),
        0,
        "a fail-closed refusal leaves no lasting charge"
    );

    let _ = server.shutdown.send(());
}

// ── The shared bucket clock is Redis's own (review round 3 of PR #5584) ───
//
// Sub-buckets are only as shared as the clock that selects them. The forward
// `GET` covers ONE sub-bucket of drift, and it has to spend that allowance on
// transaction staleness; asking it to absorb clock skew as well lets a pair of
// gateways consume it twice and both be admitted. Every charge transaction
// therefore carries a `TIME`, and selection plus settlement run on the offset
// it teaches the client.

/// The offset arithmetic itself, without a server: integer, saturating, and
/// clamped at the epoch.
#[test]
fn a_learned_offset_shifts_the_local_clock_onto_the_server_clock() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        RedisServerClock, apply_clock_offset, clock_offset_nanos,
    };

    let local = Duration::from_millis(100_251);
    let server = Duration::from_millis(100_151);
    let offset = clock_offset_nanos(server, local);
    assert_eq!(offset, -100_000_000, "a gateway 100ms fast learns -100ms");
    assert_eq!(apply_clock_offset(local, offset), server);

    let behind = clock_offset_nanos(Duration::from_millis(500), Duration::from_millis(200));
    assert_eq!(behind, 300_000_000);
    assert_eq!(
        apply_clock_offset(Duration::from_millis(200), behind),
        Duration::from_millis(500)
    );

    // A nonsense offset clamps at the epoch instead of wrapping into a
    // plausible-looking sub-bucket at the far end of the index space.
    assert_eq!(
        apply_clock_offset(Duration::from_millis(1), i64::MIN),
        Duration::ZERO
    );

    // Unsampled, the clock IS the local clock; one reply is enough to move it.
    let clock = RedisServerClock::new();
    assert_eq!(clock.offset_nanos(), None);
    assert_eq!(clock.at(local), local);
    clock.record_reply(server, local);
    assert_eq!(clock.offset_nanos(), Some(-100_000_000));
    assert_eq!(clock.at(local), server);
    assert_eq!(
        clock.at(local + Duration::from_millis(40)),
        server + Duration::from_millis(40),
        "the correction is an offset, not a pinned instant"
    );
}

/// A `TIME` reply is accepted only in the exact shape Redis documents.
#[test]
fn a_server_time_reply_is_parsed_strictly_or_not_at_all() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::parse_redis_server_time;

    let ok = redis::Value::Array(vec![
        redis::Value::BulkString(b"100".to_vec()),
        redis::Value::BulkString(b"151000".to_vec()),
    ]);
    assert_eq!(
        parse_redis_server_time(ok),
        Some(Duration::from_millis(100_151))
    );

    for rejected in [
        // Not an array at all: a server that answered `+OK` to `TIME`.
        redis::Value::Okay,
        // One element, or three: a shape this code cannot pair with a clock.
        redis::Value::Array(vec![redis::Value::BulkString(b"100".to_vec())]),
        redis::Value::Array(vec![
            redis::Value::BulkString(b"100".to_vec()),
            redis::Value::BulkString(b"1".to_vec()),
            redis::Value::BulkString(b"1".to_vec()),
        ]),
        // A microsecond field outside its second.
        redis::Value::Array(vec![
            redis::Value::BulkString(b"100".to_vec()),
            redis::Value::BulkString(b"1000000".to_vec()),
        ]),
        // Non-numeric text.
        redis::Value::Array(vec![
            redis::Value::BulkString(b"now".to_vec()),
            redis::Value::BulkString(b"0".to_vec()),
        ]),
    ] {
        // The parse consumes the reply, so render the shape before handing it over.
        let rendered = format!("{rejected:?}");
        assert_eq!(
            parse_redis_server_time(rejected),
            None,
            "an unusable server clock must never be guessed at: {rendered}"
        );
    }
}

/// Review finding 1, first counterexample: skew PLUS transaction staleness.
///
/// Gateway B's clock runs 100ms ahead of A's. On their own clocks A samples
/// `100.124` (bucket 1601) and B samples `100.251` (bucket 1604) for the same
/// real instant `100.151`; B executes first, A's ladder stops at `1602`, and
/// both are admitted against a one-request quota. Corrected onto the one server
/// clock both pick adjacent buckets, so whichever lands second sees the other.
#[tokio::test]
async fn skewed_gateways_corrected_to_the_server_clock_cannot_double_admit() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisServerClock, RedisWindowCharges};

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions::default()).await;
    let client = keyspace_client(server.port);

    // Gateway A's clock IS the server's; gateway B's runs 100ms fast. Each
    // learns its own offset from a `TIME` reply taken at its own local instant.
    let a_clock = RedisServerClock::new();
    a_clock.record_reply(Duration::from_millis(90_000), Duration::from_millis(90_000));
    let b_clock = RedisServerClock::new();
    b_clock.record_reply(Duration::from_millis(90_000), Duration::from_millis(90_100));
    assert_eq!(a_clock.offset_nanos(), Some(0));
    assert_eq!(b_clock.offset_nanos(), Some(-100_000_000));

    // The real instants: A at 100.124 on the server clock, B 27ms later.
    let a_local = Duration::from_micros(100_124_000);
    let b_local = Duration::from_micros(100_251_000);

    let a_raw = RedisRateLimitClient::sub_bucket_at(a_local, 1);
    let b_raw = RedisRateLimitClient::sub_bucket_at(b_local, 1);
    assert_eq!(a_raw.index, 1_601);
    assert_eq!(
        b_raw.index, 1_604,
        "on its own fast clock B selects three buckets past A's — the gap the \
         forward GET cannot cover"
    );

    let a_bucket = RedisRateLimitClient::sub_bucket_at(a_clock.at(a_local), 1);
    let b_bucket = RedisRateLimitClient::sub_bucket_at(b_clock.at(b_local), 1);
    assert_eq!(a_bucket.index, 1_601);
    assert_eq!(
        b_bucket.index, 1_602,
        "corrected onto the server clock the two land in ADJACENT sub-buckets"
    );

    let mut a_charge = RedisWindowCharges::default();
    assert!(a_charge.push(client.window_charge("ip:127.0.0.1", a_bucket, 3)));
    let mut b_charge = RedisWindowCharges::default();
    assert!(b_charge.push(client.window_charge("ip:127.0.0.1", b_bucket, 3)));

    // B executes FIRST, exactly as the finding describes.
    let b_counts = client
        .charge_rate_limit_windows(b_charge.as_slice())
        .await
        .expect("B's transaction must execute");
    let a_counts = client
        .charge_rate_limit_windows(a_charge.as_slice())
        .await
        .expect("A's transaction must execute");

    let limit = 1_u64;
    let admitted = [&b_counts, &a_counts]
        .iter()
        .filter(|counts| counts.as_slice()[0] <= limit)
        .count();
    assert_eq!(
        admitted, 1,
        "exactly one of two requests inside one trailing second may be admitted; \
         b={b_counts:?} a={a_counts:?}"
    );
    assert_eq!(
        a_counts.as_slice()[0],
        2,
        "A must observe B one bucket ahead"
    );

    // What the uncorrected pair would have read: A's ladder stops at 801 and
    // never reaches B's charge in 802, so BOTH would have been admitted. Read
    // straight off the fake keyspace.
    let mut uncorrected = RedisWindowCharges::default();
    assert!(uncorrected.push(client.window_charge("ip:127.0.0.1", b_raw, 3)));
    let skewed_slot = &uncorrected.as_slice()[0];
    let skewed_key = skewed_slot.charged_key().to_string();
    let a_slot = &a_charge.as_slice()[0];
    let mut a_ladder: Vec<String> = a_slot.trailing_keys().map(str::to_string).collect();
    a_ladder.push(a_slot.charged_key().to_string());
    a_ladder.push(a_slot.next_key().to_string());
    assert!(
        !a_ladder.contains(&skewed_key),
        "the skewed bucket is outside A's ladder, which is exactly the \
         over-admission the server clock removes"
    );

    let _ = server.shutdown.send(());
}

/// Review finding 1, second counterexample: skew alone, at the OLDEST end.
///
/// No transaction delay at all. A admits at `100.124` (bucket 1601). 976ms
/// later B, whose clock is 100ms fast, reads `101.200` and selects bucket 1619,
/// whose ladder starts at 1602 — dropping A's admission although it is still
/// inside the real trailing second. Corrected onto the server clock B selects
/// 1617 and its ladder still covers 1601.
#[tokio::test]
async fn a_skewed_gateway_corrected_to_the_server_clock_keeps_the_oldest_live_charge() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisServerClock, RedisWindowCharges};

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions::default()).await;
    let client = keyspace_client(server.port);

    let b_clock = RedisServerClock::new();
    b_clock.record_reply(Duration::from_millis(90_000), Duration::from_millis(90_100));

    let a_bucket = RedisRateLimitClient::sub_bucket_at(Duration::from_micros(100_124_000), 1);
    assert_eq!(a_bucket.index, 1_601);
    let mut a_charge = RedisWindowCharges::default();
    assert!(a_charge.push(client.window_charge("ip:127.0.0.1", a_bucket, 3)));
    let a_counts = client
        .charge_rate_limit_windows(a_charge.as_slice())
        .await
        .expect("A's admission must execute");
    assert_eq!(a_counts.as_slice()[0], 1);
    let a_key = a_charge.as_slice()[0].charged_key().to_string();

    // B's own clock reads 101.200 for the real instant 101.100.
    let b_local = Duration::from_micros(101_200_000);
    let b_raw = RedisRateLimitClient::sub_bucket_at(b_local, 1);
    let b_bucket = RedisRateLimitClient::sub_bucket_at(b_clock.at(b_local), 1);
    assert_eq!(b_raw.index, 1_619);
    assert_eq!(b_bucket.index, 1_617);

    let mut skewed = RedisWindowCharges::default();
    assert!(skewed.push(client.window_charge("ip:127.0.0.1", b_raw, 3)));
    let raw_slot = &skewed.as_slice()[0];
    let raw_ladder: Vec<String> = raw_slot.trailing_keys().map(str::to_string).collect();
    assert!(
        !raw_ladder.contains(&a_key),
        "on its own fast clock B drops a still-live charge off the oldest end"
    );

    let mut corrected = RedisWindowCharges::default();
    assert!(corrected.push(client.window_charge("ip:127.0.0.1", b_bucket, 3)));
    let fixed_slot = &corrected.as_slice()[0];
    let fixed_ladder: Vec<String> = fixed_slot.trailing_keys().map(str::to_string).collect();
    assert!(
        fixed_ladder.contains(&a_key),
        "corrected onto the server clock the oldest live sub-bucket is still read"
    );

    let b_counts = client
        .charge_rate_limit_windows(corrected.as_slice())
        .await
        .expect("B's transaction must execute");
    assert_eq!(
        b_counts.as_slice()[0],
        2,
        "B must count A's still-live admission; a one-request quota refuses it"
    );

    let _ = server.shutdown.send(());
}

/// The offset is seeded from the connection probe BEFORE the first selection,
/// and refreshed by every `EXEC` after it.
///
/// The fake server's clock runs ten minutes ahead of this process's, so a
/// gateway that selected buckets from its own wall clock would write keys ten
/// minutes away from the ones every other gateway charges. Bucket selection
/// would otherwise precede connection acquisition, so `check_http_windows_redis`
/// establishes the connection — and therefore runs its `TIME` probe — first.
/// The startup rollover this replaces cost an extra transaction AND left the
/// abandoned charge on a ladder no peer shares until its TTL elapsed.
#[tokio::test]
async fn a_charge_transaction_teaches_the_client_the_server_clock() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::redis_epoch_now;

    const SHIFT: Duration = Duration::from_secs(600);
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Ahead(SHIFT),
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    // Before any connection there is no sample, and the clock IS the local one.
    assert_eq!(
        client.server_clock().offset_nanos(),
        None,
        "a client that has never reached Redis has no offset to apply"
    );
    let local_before = redis_epoch_now();
    let unsampled = client.server_clock().at(local_before);
    assert_eq!(unsampled, local_before);

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    // The bucket a raw local selection would have chosen, captured before the
    // client has ever connected. Ten minutes is 9600 sub-buckets of a
    // one-second window, so it could never be mistaken for a server bucket.
    let local_bucket = RedisRateLimitClient::sub_bucket_at(redis_epoch_now(), 1).index;

    // The FIRST request of a client's life seeds its offset from the connection
    // probe before it selects, so it charges the SERVER's bucket directly: one
    // transaction, no hand-back, no rebuild.
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("the charge must land")
            .allowed
    );

    let offset = client
        .server_clock()
        .offset_nanos()
        .expect("the connection probe must teach the client the server clock");
    let shift_nanos = SHIFT.as_nanos() as i64;
    assert!(
        (offset - shift_nanos).abs() < 5_000_000_000,
        "the learned offset must be the server's ten-minute lead, not zero: {offset}"
    );

    assert_eq!(
        server.incrs(),
        1,
        "a seeded first selection charges once; the startup rollover is gone"
    );
    assert_eq!(server.decrs(), 0, "and hands nothing back");
    let charged = charged_sub_buckets(&server);
    assert_eq!(
        charged.len(),
        1,
        "exactly one sub-bucket is touched, on the server clock: {charged:?}"
    );
    let (server_index, server_count) = charged[0];
    assert_eq!(server_count, 1);
    assert!(
        server_index - local_bucket > 9_000,
        "the charged bucket must be the SERVER's: local={local_bucket} \
         server={server_index}"
    );

    // And the NEXT request stays on the server clock.
    let charges_before = server.incrs();
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("the second charge must land")
            .allowed
    );
    assert_eq!(
        server.incrs() - charges_before,
        1,
        "a learned offset means the next selection needs no rebuild"
    );
    let charged = charged_sub_buckets(&server);
    let newest = charged.last().copied().expect("a charged sub-bucket");
    assert!(
        newest.0.abs_diff(server_index) <= 1,
        "the second request must charge on the SERVER clock too: \
         first={server_index} second={}",
        newest.0
    );
    assert!(
        newest.0.abs_diff(local_bucket) > 9_000,
        "and never back on this process's own clock: local={local_bucket} \
         second={}",
        newest.0
    );

    let _ = server.shutdown.send(());
}

/// Settlement is judged on the server's clock at `EXEC`, not on a local sample
/// taken after the reply arrives.
///
/// The transaction executes on time and only its REPLY is held for four whole
/// sub-buckets. A local post-`EXEC` sample would read `b + 4` and roll the
/// ladder over for nothing; the server's own `TIME` says `b`, and reply latency
/// after `EXEC` is harmless because a peer charging later reads this request's
/// own increment.
#[tokio::test]
async fn settlement_is_judged_on_the_server_clock_not_a_local_post_exec_sample() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(250),
        delayed_charges: 1,
        hold_phase: HoldPhase::AfterApply,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let outcome = algorithm
        .check_redis(&client, "ip:127.0.0.1", &op)
        .await
        .expect("a late REPLY is not a stale ladder");
    assert!(outcome.allowed);

    assert_eq!(
        server.incrs(),
        1,
        "the ladder executed inside its own sub-bucket, so nothing may be rebuilt"
    );
    assert_eq!(
        server.decrs(),
        0,
        "nothing was abandoned, so nothing is handed back"
    );
    assert_eq!(client.pending_compensations_for_test(), 0);

    let _ = server.shutdown.send(());
}

/// Review finding 2: a rebuilt ladder must not count the charge its own
/// abandoned pass left behind.
///
/// The rebuilt ladder reads the sub-bucket the abandoned pass charged, so
/// dispatching the hand-back is not enough — the rebuild has to wait for the
/// `DECR` to land. With a one-request quota and a deliberately slow
/// compensation, a rebuild that raced ahead would read its own abandoned charge
/// plus its new one, see usage `2`, and refuse a request the quota admits.
#[tokio::test]
async fn a_rebuilt_ladder_does_not_count_the_charge_it_abandoned() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    // Timing budget, all against a TWO-second window's 125ms sub-buckets. The
    // window is two seconds rather than one so the margins below stay where
    // they were when `K` was eight: at `K = 16` a one-second window's
    // sub-buckets are 62.5ms, which the 80ms hand-back hold would itself
    // straddle.
    //
    // - The first charge stalls 250ms BEFORE executing, so the server applies
    //   it exactly two sub-buckets late and its own `TIME` proves the rollover.
    //   250ms stays inside the 500ms screened per-command response deadline.
    // - Its hand-back is then held 80ms, which is long enough that a rebuild
    //   which only DISPATCHED the compensation would reach the server first,
    //   and short enough (< one sub-bucket) that the rebuilt ladder cannot roll
    //   over in turn and turn this into the two-rollover refusal.
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(250),
        delayed_charges: 1,
        hold_phase: HoldPhase::BeforeApply,
        compensation_delay: Duration::from_millis(80),
        delayed_compensations: 1,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1,
        duration: Duration::from_secs(2),
    }]);
    let outcome = algorithm
        .check_redis(&client, "ip:127.0.0.1", &op)
        .await
        .expect("the rebuilt pass must produce a decision");
    assert!(
        outcome.allowed,
        "an empty one-request quota admits: the abandoned charge was handed \
         back before the rebuilt ladder read its bucket"
    );

    for _ in 0..6_000 {
        if client.pending_compensations_for_test() == 0 && server.decrs() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(server.incrs(), 2, "the abandoned pass and the rebuild");
    assert_eq!(server.decrs(), 1, "exactly one hand-back");
    // The decisive ordering, read off the keyspace rather than off the clock:
    // the hand-back must be APPLIED between the abandoned charge and the
    // rebuild. Dispatch order alone would put the rebuild's `INCR` second.
    assert_eq!(
        server.ops(),
        vec!["INCR", "DECR", "INCR"],
        "the rebuild must execute only after its own hand-back landed"
    );
    assert_eq!(
        server.charged_total(),
        1,
        "exactly one charge survives: the admitted request's"
    );

    let _ = server.shutdown.send(());
}

/// A hand-back that cannot be confirmed refuses instead of rebuilding.
///
/// The compensation is held past the screened per-command deadline that bounds
/// the confirmation, so the rebuild would have to read a bucket that still
/// holds the abandoned charge. Refusing routes the request through
/// `redis_failure_policy` (an unavailable centralized store) rather than
/// publishing a quota decision derived from a charge this request abandoned.
#[tokio::test]
async fn a_rollover_whose_hand_back_is_unconfirmed_refuses_instead_of_rebuilding() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(250),
        delayed_charges: 1,
        hold_phase: HoldPhase::BeforeApply,
        // Past both the 500ms screened per-command deadline and the equal
        // bound on the confirmation wait.
        compensation_delay: Duration::from_millis(900),
        delayed_compensations: 1,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        result.is_err(),
        "an unconfirmed hand-back must refuse through redis_failure_policy, \
         not rebuild against its own abandoned charge: {result:?}"
    );
    assert_eq!(
        server.incrs(),
        1,
        "the rebuild must never be issued once the hand-back is in doubt"
    );

    let _ = server.shutdown.send(());
}

/// An endpoint whose ACL refuses `TIME` is an UNUSABLE store, not a weaker
/// contract.
///
/// `TIME` is a hard requirement: the bucket clock is the only thing that makes
/// sub-buckets shared, so a connection that cannot answer it is discarded
/// exactly like one that failed the Cluster screen, and `redis_failure_policy`
/// decides from there. The earlier "local-clock mode" — selecting buckets from
/// each gateway's own wall clock under a documented skew contract — is gone: it
/// kept admitting centrally against ladders that were not shared.
///
/// The probe is still a STANDALONE command, because a denied command queued
/// inside `MULTI` aborts the whole `EXEC` and the endpoint has to be rejected
/// before it can carry a policy command at all.
#[tokio::test]
async fn an_acl_that_denies_time_makes_the_store_unavailable() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Denied,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        result.is_err(),
        "a denied TIME must refuse through redis_failure_policy rather than admit on a \
         clock no peer shares: {result:?}"
    );
    assert!(
        !client.is_available(),
        "the connection could not be screened, so the store is unavailable"
    );
    assert_eq!(
        client.server_clock().offset_nanos(),
        None,
        "no clock was learned, and none is invented"
    );
    assert_eq!(
        server.incrs(),
        0,
        "no policy command may run on a connection that could not be screened"
    );

    let _ = server.shutdown.send(());
}

/// Reply-shape validation for the server-clock transaction: a reply this code
/// cannot pair with its windows is an unusable ENDPOINT, never a quota
/// decision.
///
/// The `INCR`s have already landed when the mismatch is seen, so the client
/// marks itself unavailable and hands the next decision to
/// `redis_failure_policy` rather than re-charging a reply it cannot read on
/// every request.
#[tokio::test]
async fn a_charge_reply_with_an_extra_element_is_refused_in_server_clock_mode() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        extra_exec_element: true,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    // The probe runs when the pool slot is established — inside that first
    // charge — so the mode is observable only afterwards.
    assert!(
        client.server_clock().offset_nanos().is_some(),
        "the probe must have seeded a clock for this to be the reply shape under test"
    );
    assert!(
        result.is_err(),
        "a reply one element longer than the ladder plus its clock must refuse: {result:?}"
    );
    assert!(
        !client.is_available(),
        "an unpairable reply is an unusable endpoint, so the NEXT decision goes \
         through redis_failure_policy instead of re-charging"
    );

    let _ = server.shutdown.send(());
}

/// A `TIME` the transaction answered with something that is not a clock fails
/// closed instead of silently falling back to this gateway's own clock.
///
/// The standalone probe succeeded, so the endpoint claimed the server-clock
/// contract. Quietly reinstating the local clock there would put the skew term
/// back into the ladder on exactly the deployments that believe they do not
/// have one.
#[tokio::test]
async fn a_transaction_clock_this_code_cannot_read_fails_closed() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::MalformedInTransaction,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    // The probe runs on connect, inside that first charge.
    assert!(
        client.server_clock().offset_nanos().is_some(),
        "the standalone probe must have succeeded for this to be the case under test"
    );
    assert!(
        result.is_err(),
        "an unreadable server clock must refuse, not read as a local instant: {result:?}"
    );
    assert!(
        !client.is_available(),
        "the endpoint claimed the server-clock contract and did not honour it"
    );

    let _ = server.shutdown.send(());
}

// ── Learned offsets are not an exact clock (review round 4 of PR #5584) ───
//
// `server_time − local_time_at_reply` is sampled one REPLY LATENCY after the
// server read its clock, so two gateways sharing a quota select on corrected
// clocks that differ by the difference of their latencies. The ladder is
// correct in spite of that because settlement is two-sided and the ladder reads
// one sub-bucket further back than its own window.

/// Review finding (MAJOR 1): two gateways with synchronized host clocks and
/// different Redis reply latencies still select sub-buckets `K + 1` apart, and
/// a `K`-deep trailing ladder drops the older one while it is still live.
///
/// A's reply is decoded 10ms after the server read its clock, B's 1ms after, so
/// their learned offsets are −10ms and −1ms. A admits at real `100.009` and B
/// 993ms later at real `101.002` — inside one trailing second, so a `1/s` quota
/// may admit exactly one of them. A's key is `1599`, B's is `1616`: seventeen
/// apart, which is one further than a `K`-deep ladder reaches.
///
/// Both charges are legitimate and retained — each settles inside its own
/// two-sided band against the instant the server applied it — so this is not a
/// case settlement can reject. The extra OLD counter is what counts it.
#[tokio::test]
async fn reply_latency_puts_a_live_charge_one_bucket_past_a_k_deep_ladder() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        REDIS_WINDOW_TRAILING_SUB_BUCKETS, RedisServerClock, RedisWindowCharges,
        sub_bucket_charge_is_settled,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions::default()).await;
    let client = keyspace_client(server.port);

    // Synchronized host clocks; only the reply latencies differ.
    let a_clock = RedisServerClock::new();
    a_clock.record_reply(Duration::from_millis(90_000), Duration::from_millis(90_010));
    let b_clock = RedisServerClock::new();
    b_clock.record_reply(Duration::from_millis(90_000), Duration::from_millis(90_001));
    assert_eq!(a_clock.offset_nanos(), Some(-10_000_000));
    assert_eq!(b_clock.offset_nanos(), Some(-1_000_000));

    let a_local = Duration::from_micros(100_009_000);
    let b_local = Duration::from_micros(101_002_000);
    assert!(
        b_local - a_local < Duration::from_secs(1),
        "the two admissions must lie inside ONE trailing second"
    );

    let a_bucket = RedisRateLimitClient::sub_bucket_at(a_clock.at(a_local), 1);
    let b_bucket = RedisRateLimitClient::sub_bucket_at(b_clock.at(b_local), 1);
    assert_eq!(a_bucket.index, 1_599);
    assert_eq!(b_bucket.index, 1_616);
    assert_eq!(
        (b_bucket.index - a_bucket.index) as usize,
        REDIS_WINDOW_TRAILING_SUB_BUCKETS,
        "exactly the depth the extra old counter adds"
    );

    // Neither charge is something settlement may reject: each lands in its own
    // two-sided band against the instant the server applies it.
    assert!(sub_bucket_charge_is_settled(a_bucket, a_local));
    assert!(sub_bucket_charge_is_settled(b_bucket, b_local));

    let mut a_charge = RedisWindowCharges::default();
    assert!(a_charge.push(client.window_charge("ip:127.0.0.1", a_bucket, 3)));
    let mut b_charge = RedisWindowCharges::default();
    assert!(b_charge.push(client.window_charge("ip:127.0.0.1", b_bucket, 3)));

    let a_counts = client
        .charge_rate_limit_windows(a_charge.as_slice())
        .await
        .expect("A's admission must execute");
    assert_eq!(a_counts.as_slice()[0], 1);
    let b_counts = client
        .charge_rate_limit_windows(b_charge.as_slice())
        .await
        .expect("B's transaction must execute");

    let limit = 1_u64;
    let admitted = [&a_counts, &b_counts]
        .iter()
        .filter(|counts| counts.as_slice()[0] <= limit)
        .count();
    assert_eq!(
        admitted, 1,
        "exactly one of two requests 993ms apart may be admitted against a 1/s \
         quota; a={a_counts:?} b={b_counts:?}"
    );
    assert_eq!(
        b_counts.as_slice()[0],
        2,
        "B must count A's still-live admission at the OLDEST end of its ladder"
    );

    // What a `K`-deep trailing ladder would have summed: drop the oldest
    // counter and A's charge disappears, so both would have been admitted.
    let b_slot = &b_charge.as_slice()[0];
    let trailing: Vec<String> = b_slot.trailing_keys().map(str::to_string).collect();
    let mut narrower = trailing[1..].to_vec();
    narrower.push(b_slot.charged_key().to_string());
    narrower.push(b_slot.next_key().to_string());
    let narrower_total: i64 = narrower.iter().map(|key| server.counter(key)).sum();
    assert_eq!(
        narrower_total, 1,
        "without the extra old counter the ladder sums to 1 and over-admits"
    );

    let _ = server.shutdown.send(());
}

/// The steady-state quantisation at `K = 16`, swept across limits and placement
/// lags.
///
/// Two closed forms, and every document has to keep them apart. A HOMOGENEOUS
/// stream — every request placing its charge the same way — keeps
/// `limit / (limit + ceil(2 * limit / K))`, because the ladder reads `K + 1`
/// older counters rather than `K`. The BOUND the module docs,
/// `docs/plugins.md`, and the CHANGELOG state is
/// `limit / (limit + ceil(3 * limit / K))`, one sub-bucket wider, because a
/// reader whose transaction straddles a sub-bucket boundary reads a ladder
/// built one bucket before the bucket it executes in
/// (`placement_lag_widens_the_counted_history_to_three_sub_buckets`).
///
/// Shifting every request by the SAME latency moves no key, so the measured
/// fraction is the homogeneous one at every lag; this sweep is what would catch
/// a future change to either constant that quietly moved either figure.
#[test]
fn the_steady_rate_model_matches_the_documented_fraction_at_k_sixteen() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_WINDOW_SUB_BUCKETS;

    const NANOS_PER_SECOND: u64 = 1_000_000_000;
    let sub_bucket_nanos = NANOS_PER_SECOND / REDIS_WINDOW_SUB_BUCKETS as u64;

    for limit in [1_u64, 2, 4, 8, 16, 32, 100] {
        let spacing_nanos = NANOS_PER_SECOND / limit;
        assert_eq!(
            spacing_nanos * limit,
            NANOS_PER_SECOND,
            "limit {limit}: the arrival spacing must divide the window exactly"
        );
        for latency in [
            Duration::ZERO,
            Duration::from_nanos(sub_bucket_nanos / 2),
            Duration::from_nanos(sub_bucket_nanos),
        ] {
            // Five seconds of warm-up so the ladder is full, then forty seconds
            // of steady traffic at exactly the configured rate.
            let warmup = limit * 5;
            let offered = limit * 45;
            let mut buckets = std::collections::HashMap::new();
            let mut admitted = 0_u64;
            for attempt in 0..offered {
                let at = Duration::from_nanos(100 * NANOS_PER_SECOND + attempt * spacing_nanos);
                if model_sub_bucket_admits(&mut buckets, at, latency, 1, limit) && attempt >= warmup
                {
                    admitted += 1;
                }
            }

            let excess = (limit * 2).div_ceil(REDIS_WINDOW_SUB_BUCKETS as u64);
            let homogeneous = limit as f64 / (limit + excess) as f64;
            let bound_excess = (limit * 3).div_ceil(REDIS_WINDOW_SUB_BUCKETS as u64);
            let bound = limit as f64 / (limit + bound_excess) as f64;
            let measured = admitted as f64 / (offered - warmup) as f64;
            assert!(
                (measured - homogeneous).abs() < 0.02,
                "limit {limit} at latency {latency:?}: measured {measured} vs homogeneous \
                 {homogeneous}"
            );
            assert!(
                measured + 0.02 >= bound,
                "limit {limit} at latency {latency:?}: measured {measured} below the \
                 documented bound {bound}"
            );
            assert!(
                measured >= 0.49,
                "limit {limit} at latency {latency:?}: even the worst small quota keeps half \
                 its rate ({measured})"
            );
        }
    }
}

// ── A gateway ahead of Redis (review round 4, MAJOR 2) ────────────────────
//
// Settlement now refuses BOTH directions. A charge placed in the future is
// invisible to every peer reading its own trailing window, so accepting it let
// an unsampled fast gateway charge an unreachable ladder and then admit again
// on the corrected one.

/// Redis BEHIND the gateway, with the shared budget already consumed by a peer:
/// the second gateway must not admit.
///
/// The fake server's clock runs ten minutes behind this process's, so a gateway
/// selecting on its own wall clock would charge 9600 sub-buckets into the
/// future — a ladder no peer's trailing window reaches.
#[tokio::test]
async fn a_gateway_ahead_of_redis_cannot_double_admit_a_consumed_peer_budget() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::redis_epoch_now;

    const SHIFT: Duration = Duration::from_secs(600);
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Behind(SHIFT),
        ..KeyspaceServerOptions::default()
    })
    .await;
    let peer = Arc::new(keyspace_client(server.port));
    let latecomer = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1,
        duration: Duration::from_secs(1),
    }]);

    // The peer consumes the one-request budget on the SERVER's clock.
    assert!(
        algorithm
            .check_redis(&peer, "ip:127.0.0.1", &op)
            .await
            .expect("the peer's charge must land")
            .allowed
    );
    let peer_keys = server.keys();
    assert_eq!(peer_keys.len(), 1, "one charged sub-bucket: {peer_keys:?}");
    let peer_key = peer_keys[0].clone();

    // What an uncorrected selection would have charged: a bucket 9600
    // sub-buckets away, whose ladder cannot reach the peer's key at all.
    let raw_bucket = RedisRateLimitClient::sub_bucket_at(redis_epoch_now(), 1);
    let raw = latecomer.window_charge("ip:127.0.0.1", raw_bucket, 3);
    let mut raw_ladder: Vec<String> = raw.trailing_keys().map(str::to_string).collect();
    raw_ladder.push(raw.charged_key().to_string());
    raw_ladder.push(raw.next_key().to_string());
    assert!(
        !raw_ladder.contains(&peer_key),
        "the raw-local ladder misses the peer's charge entirely, which is the \
         double admission this closes"
    );

    // The second gateway seeds from the probe, selects the server's bucket, and
    // sees the peer.
    let second = algorithm
        .check_redis(&latecomer, "ip:127.0.0.1", &op)
        .await
        .expect("the second gateway's transaction must execute");
    assert!(
        !second.allowed,
        "a 1/s quota already consumed by a peer must refuse the second gateway"
    );
    let offset = latecomer
        .server_clock()
        .offset_nanos()
        .expect("the probe must teach the latecomer the server clock");
    assert!(
        offset < -500_000_000_000,
        "the learned offset must be the server's ten-minute LAG: {offset}"
    );

    let _ = server.shutdown.send(());
}

/// A charge the server applies BEFORE the bucket it was keyed to is compensated
/// and rebuilt on the server clock.
///
/// The client learns a correct offset, then Redis steps ten minutes backward.
/// The stale offset puts the next selection 9600 sub-buckets into the future,
/// where no peer's trailing window reaches it. Settlement's early end catches
/// exactly that.
#[tokio::test]
async fn a_charge_placed_in_the_future_is_compensated_and_rebuilt() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    const SHIFT: Duration = Duration::from_secs(600);
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions::default()).await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("the first charge must land")
            .allowed
    );
    assert_eq!(server.incrs(), 1);

    // Redis steps backward; the client's offset is now stale in the direction
    // that places its charge in the future.
    server.set_time_mode(ServerTimeMode::Behind(SHIFT));
    let charges_before = server.incrs();
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("the rebuilt pass must produce a decision")
            .allowed
    );
    assert_eq!(
        server.incrs() - charges_before,
        2,
        "the future placement and its rebuild are two charges, and no more"
    );

    for _ in 0..6_000 {
        if client.pending_compensations_for_test() == 0 && server.decrs() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        server.decrs(),
        1,
        "the future placement must hand its own charge back"
    );
    assert_eq!(
        server.charged_total(),
        2,
        "the first admission and the rebuilt one, and nothing stranded"
    );

    let charged = charged_sub_buckets(&server);
    let oldest = *charged.first().expect("a charged sub-bucket");
    let newest = *charged.last().expect("a charged sub-bucket");
    assert!(
        newest.0 - oldest.0 > 9_000,
        "the rebuilt charge must sit on the server's stepped-back clock: \
         {charged:?}"
    );
    assert_eq!(oldest.1, 1, "and it is the one that stands: {charged:?}");

    let _ = server.shutdown.send(());
}

// ── The TIME probe degrades only on a recognised verdict (round 4, MAJOR 3) ─
//
// `NOPERM` and `ERR unknown command` are permanent statements about what the
// endpoint offers. A malformed reply, a timeout, and a transport failure are
// not: they are connections that could not be screened, and collapsing them
// into a silent local-clock mode let an explicit `fail_closed` policy keep
// admitting against an endpoint that could not answer its own clock. Every one
// of them now rejects the connection, exactly as a `NOPERM` does.

/// A server that answers `TIME` with something that is not a clock is an
/// unusable endpoint, not an ACL verdict.
#[tokio::test]
async fn a_time_probe_that_answers_a_non_clock_is_an_unusable_endpoint() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::MalformedProbe,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        result.is_err(),
        "an unreadable probe must refuse through redis_failure_policy, not admit \
         on a quietly weakened contract: {result:?}"
    );
    assert!(!client.is_available());
    assert_eq!(
        client.server_clock().offset_nanos(),
        None,
        "a reply this code cannot pair with a clock teaches no offset"
    );
    assert_eq!(
        server.incrs(),
        0,
        "no policy command may run on a connection that could not be screened"
    );

    let _ = server.shutdown.send(());
}

/// A probe that never answers inside the screened per-command deadline is an
/// unusable endpoint.
#[tokio::test]
async fn a_time_probe_that_never_answers_is_an_unusable_endpoint() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::ProbeTimeout,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(result.is_err(), "a silent probe must refuse: {result:?}");
    assert!(!client.is_available());
    assert_eq!(client.server_clock().offset_nanos(), None);
    assert_eq!(server.incrs(), 0);

    let _ = server.shutdown.send(());
}

/// A probe whose connection drops is an unusable endpoint.
#[tokio::test]
async fn a_time_probe_whose_connection_drops_is_an_unusable_endpoint() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::ProbeTransportError,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        result.is_err(),
        "a transport failure on the probe must refuse: {result:?}"
    );
    assert!(!client.is_available());
    assert_eq!(client.server_clock().offset_nanos(), None);
    assert_eq!(server.incrs(), 0);

    let _ = server.shutdown.send(());
}

/// A RESP-compatible server that does not implement `TIME` is an unusable
/// store, exactly like a `NOPERM`.
///
/// The two answers differ only in the diagnostic they produce — "grant `+time`"
/// versus "this server has no `TIME`" — never in the outcome.
#[tokio::test]
async fn a_server_that_does_not_implement_time_is_an_unusable_endpoint() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::UnknownCommand,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let result = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        result.is_err(),
        "a server without TIME cannot back a shared request quota: {result:?}"
    );
    assert!(!client.is_available());
    assert_eq!(client.server_clock().offset_nanos(), None);
    assert_eq!(
        server.incrs(),
        0,
        "no policy command may run on a connection that could not be screened"
    );

    let _ = server.shutdown.send(());
}

// ── The `TIME` requirement is scoped to the consumers that read the clock ──
//
// Connection screening is shared by every consumer of `RedisRateLimitClient`,
// so making the probe a property of the SOCKET made `+time` mandatory for
// `request_deduplication`, `soap_ws_security`'s shared replay authority,
// `ai_semantic_cache`, and the three token/frame/datagram budgets — none of
// which ever selects a sub-bucket. The requirement is therefore declared at
// construction, and enforced at both ends: the probe runs only for a
// request-quota client, and the ladder refuses to charge on any other.

/// A consumer that reads no server clock never sends `TIME`, so an endpoint
/// whose ACL denies it stays fully usable for that consumer.
///
/// The same fixture refuses the request-quota client on the same connection
/// screen, which is what keeps the two halves of this test honest: the endpoint
/// is identical, only the declared requirement differs.
#[tokio::test]
async fn only_a_request_quota_client_probes_the_server_clock() {
    use ferrum_edge::_test_support::redis_client_without_server_clock_for_test;

    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Denied,
        ..KeyspaceServerOptions::default()
    })
    .await;

    // A replay / idempotency / cache / token-budget client: no probe, no
    // refusal, and the endpoint's missing `+time` grant is none of its business.
    let clockless = redis_client_without_server_clock_for_test(keyspace_config(server.port));
    let counted = clockless.incr_with_expire("ferrum:clockless:key", 60).await;
    assert_eq!(
        counted,
        Ok(1),
        "a consumer that reads no clock must not be refused by a TIME ACL"
    );
    assert!(
        clockless.is_available(),
        "an endpoint that denies TIME is still a usable marker/counter store"
    );
    assert_eq!(
        clockless.server_clock().offset_nanos(),
        None,
        "a clockless consumer learns no offset because it asks for none"
    );
    assert_eq!(
        server.clock_probes(),
        0,
        "no standalone TIME may be sent on behalf of a consumer that reads no clock"
    );

    // The request-quota client, against the very same endpoint. The clockless
    // client above legitimately ran one INCR; only the delta from here on
    // says whether a policy command ran on an unscreened connection.
    let incrs_before = server.incrs();
    let quota = keyspace_client(server.port);
    let bucket = RedisRateLimitClient::sub_bucket_at(Duration::from_secs(100), 1);
    let charge = quota.window_charge("ip:127.0.0.1", bucket, 3);
    assert!(
        quota.charge_rate_limit_windows(&[charge]).await.is_err(),
        "a shared ladder cannot be charged against an endpoint that denies TIME"
    );
    assert!(!quota.is_available());
    assert!(
        server.clock_probes() >= 1,
        "the request-quota client must screen the server clock before it charges"
    );
    assert_eq!(
        server.incrs(),
        incrs_before,
        "no policy command may run on a connection that could not be screened"
    );

    let _ = server.shutdown.send(());
}

/// Charging a ladder on a client that never declared the requirement is a
/// wiring mistake, and it fails closed.
///
/// Such a client never probed `TIME`, so its `RedisServerClock` offset is
/// unseeded and every sub-bucket would be selected from this gateway's raw
/// local clock — precisely the local-clock mode the layout exists to refuse.
/// The guard runs before any connection is acquired, so the unreachable
/// endpoint below is never dialled.
async fn charge_on_a_clockless_client_is_refused() -> bool {
    use ferrum_edge::_test_support::redis_client_without_server_clock_for_test;

    let config = make_config("redis://127.0.0.1:6379/0", false);
    let client = redis_client_without_server_clock_for_test(config);
    let bucket = RedisRateLimitClient::sub_bucket_at(Duration::from_secs(100), 1);
    let charge = client.window_charge("ip:127.0.0.1", bucket, 3);
    client.charge_rate_limit_windows(&[charge]).await.is_err()
}

/// Debug builds make the mistake loud.
#[cfg(debug_assertions)]
#[tokio::test]
#[should_panic(expected = "for_request_quota")]
async fn a_client_without_the_server_clock_requirement_cannot_charge_a_ladder() {
    let _ = charge_on_a_clockless_client_is_refused().await;
}

/// Release builds refuse instead of panicking: a proxy hot path never aborts
/// the process over a decision it can fail closed on.
#[cfg(not(debug_assertions))]
#[tokio::test]
async fn a_client_without_the_server_clock_requirement_cannot_charge_a_ladder() {
    assert!(
        charge_on_a_clockless_client_is_refused().await,
        "a ladder charged on an unseeded clock is not a shared budget"
    );
}

// ── An ACL change is an outage, not a mode change (review round 6) ────────
//
// There is ONE bucket base: the Redis server's. A gateway that cannot read it
// does not enforce centrally at all, so revoking `TIME` under a live gateway is
// an ordinary availability transition and granting it again is an ordinary
// recovery. Neither needs a second base, a transition generation, or a
// quarantine — the machinery this replaces was itself the thing a delayed reply
// could race.

/// Revoking `TIME` under a live gateway takes the store away; it does not move
/// the gateway onto a private clock.
///
/// The queued `TIME` aborts the whole `EXEC`, which is an ordinary command
/// failure: the endpoint is marked unavailable and its connections cleared, and
/// the reconnect that follows re-probes `TIME` and refuses to publish a socket
/// that cannot answer it. From the caller's side that is exactly a Redis
/// outage, and `redis_failure_policy` governs.
#[tokio::test]
async fn revoking_time_under_a_live_gateway_makes_the_store_unavailable() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    const SHIFT: Duration = Duration::from_secs(600);
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Ahead(SHIFT),
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 20,
        duration: Duration::from_secs(1),
    }]);
    // Enough requests to establish EVERY pooled slot, so the revocation below
    // is observed by a connection that was already screened rather than by a
    // fresh probe — the mid-flight case under test.
    for _ in 0..6 {
        assert!(
            algorithm
                .check_redis(&client, "ip:127.0.0.1", &op)
                .await
                .expect("every warm-up charge must land")
                .allowed
        );
    }
    let learned = client
        .server_clock()
        .offset_nanos()
        .expect("a screened connection must have learned the server clock");
    assert!(learned > 500_000_000_000, "a ten-minute lead: {learned}");

    // The ACL is revoked under the live client: the queued `TIME` aborts the
    // whole `EXEC`.
    server.set_time_mode(ServerTimeMode::Denied);
    let aborted = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        aborted.is_err(),
        "the aborted transaction is a failure, not an admission: {aborted:?}"
    );
    assert!(
        !client.is_available(),
        "an endpoint that stopped answering TIME is an unavailable store"
    );

    // And it stays unavailable: the reconnect re-probes and refuses to publish
    // a connection that cannot answer its own clock, so no request slips
    // through on a stale base. The fixture applies a transaction's queued
    // commands before it answers the denied `TIME` (a real Redis refuses at
    // queue time and aborts), so the count from the aborted pass is the
    // fixture's; what matters is that nothing runs after it.
    let charges_at_outage = server.incrs();
    assert!(client.publish_reachable_for_test());
    let after_recovery = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        after_recovery.is_err(),
        "a re-probe that is still denied must keep the store unavailable: \
         {after_recovery:?}"
    );
    assert!(!client.is_available());
    assert_eq!(
        server.incrs(),
        charges_at_outage,
        "no transaction may run on a connection the re-probe refused to publish"
    );

    let _ = server.shutdown.send(());
}

/// Granting `TIME` again is an ordinary recovery: the next screened connection
/// adopts the server clock and enforcement resumes with no quarantine.
///
/// The client starts against an endpoint that denies `TIME`, so it never
/// enforced anything and has no charges of its own on any base. Once the ACL is
/// granted, the reconnect's probe seeds the server offset and the very next
/// request selects on it.
#[tokio::test]
async fn granting_time_again_restores_centralized_enforcement() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::redis_epoch_now;

    const SHIFT: Duration = Duration::from_secs(600);
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Denied,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    let denied = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
    assert!(
        denied.is_err(),
        "a denied TIME leaves nothing to enforce with: {denied:?}"
    );
    assert!(!client.is_available());
    assert_eq!(client.server_clock().offset_nanos(), None);
    assert_eq!(server.incrs(), 0);

    // The ACL is granted, and the server's clock is ten minutes ahead of this
    // process's. Let the client retry the endpoint.
    server.set_time_mode(ServerTimeMode::Ahead(SHIFT));
    assert!(client.publish_reachable_for_test());

    let restored = algorithm
        .check_redis(&client, "ip:127.0.0.1", &op)
        .await
        .expect("a screened connection restores centralized enforcement");
    assert!(restored.allowed);
    assert!(client.is_available());
    let adopted = client
        .server_clock()
        .offset_nanos()
        .expect("the probe must have adopted the server clock");
    assert!(adopted > 500_000_000_000, "a ten-minute lead: {adopted}");
    assert_eq!(server.incrs(), 1);

    // The charge landed on the SERVER's base, ten minutes ahead of this
    // process's raw clock, which is the whole point of requiring `TIME`.
    let charged = charged_sub_buckets(&server);
    let raw = RedisRateLimitClient::sub_bucket_at(redis_epoch_now(), 1).index;
    let placed = charged.first().expect("one charged sub-bucket").0;
    assert!(
        placed > raw + 9_000,
        "the charge must sit on the server's clock, not this process's: {placed} vs {raw}"
    );

    let _ = server.shutdown.send(());
}

/// A reply delayed past one sub-bucket of the tightest window it charged must
/// not move the learned offset.
///
/// The transaction's commands apply promptly — its `TIME` reports the instant
/// the server executed them, so settlement passes — but the RESPONSE is held.
/// `server_time − local_time_at_reply` would then teach an offset short by the
/// whole hold, walking the next selection backwards by more than the ladder's
/// forward cover. The previous offset stands instead, and the charge is still
/// judged against the server instant the reply carried.
#[tokio::test]
async fn a_reply_held_past_one_sub_bucket_does_not_move_the_learned_offset() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    const SHIFT: Duration = Duration::from_secs(5);
    // 200ms is more than three sub-buckets of a one-second window, and still
    // comfortably inside the screened per-command response deadline.
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Ahead(SHIFT),
        charge_delay: Duration::from_millis(200),
        delayed_charges: usize::MAX,
        hold_phase: HoldPhase::AfterApply,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));

    // The standalone probe is not held by the charge schedule, so it seeds a
    // truthful offset first.
    client.ensure_clock_seeded().await;
    let seeded = client
        .server_clock()
        .offset_nanos()
        .expect("the probe seeds the offset");
    assert!(
        seeded > 4_500_000_000,
        "the probe must learn the server's five-second lead: {seeded}"
    );

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("the charge itself settles: only its reply was held")
            .allowed
    );

    let after = client
        .server_clock()
        .offset_nanos()
        .expect("the offset is still known");
    // The stale sample would have taught an offset roughly 200ms SMALLER, which
    // is more than three sub-buckets of walk on the next selection. Only a
    // prompt standalone probe on a second pooled slot may have refreshed it,
    // and that moves the offset by its own sub-millisecond latency.
    let moved = (after - seeded).abs();
    assert!(
        moved < 50_000_000,
        "a reply held 200ms past its transaction must not walk the learned offset: \
         moved {moved}ns (seeded {seeded}, after {after})"
    );

    let _ = server.shutdown.send(());
}

/// Background recovery must re-prove the SERVER CLOCK, not just reachability.
///
/// Review finding (MINOR 1): the recovery checker screened `PING`, topology and
/// retention and then republished availability, so a request-quota client whose
/// endpoint still denied `TIME` was advertised as recovered — and logged as
/// "centralized Redis access restored" — while every request would still fail
/// its connection probe and fall to `redis_failure_policy`. With no traffic at
/// all the false healthy state simply persisted.
///
/// Driven through the ACTUAL background checker, across denial AND restoration:
/// the transition tests elsewhere in this file publish reachability by hand,
/// which is exactly the step that could not have caught this.
#[tokio::test]
async fn background_recovery_waits_for_time_before_republishing_a_quota_client() {
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Denied,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let mut config = keyspace_config(server.port);
    // The real checker, probing once a second.
    config.health_check_interval_seconds = 1;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    // The outage a denied `TIME` produces: the connection is never published,
    // the store is unavailable, and recovery is armed.
    assert!(
        !client.connect_cached_for_test().await,
        "a connection that cannot answer TIME must never be published"
    );
    assert!(!client.is_available());
    assert!(client.health_checker_started_for_test());

    // `PING` and `INFO CLUSTER` both succeed on this endpoint, so a checker
    // that screened only reachability would republish within one interval.
    let probes_at_outage = server.clock_probes();
    tokio::time::sleep(Duration::from_millis(2_600)).await;
    let probes_after_interval = server.clock_probes();
    assert!(
        probes_after_interval > probes_at_outage,
        "the recovery probe must ask this endpoint for the server clock: \
         {probes_at_outage} -> {probes_after_interval}"
    );
    assert!(
        !client.is_available(),
        "an endpoint that still denies TIME is not a recovered quota store"
    );
    assert!(
        !client.observer_sees_available_for_test(),
        "no false recovery may be advertised to a failover health observer"
    );

    // Restoration, through the same checker: a clock refusal is retryable, not
    // terminal the way a proven Cluster topology is, so granting the ACL under
    // the live gateway is picked up on an ordinary interval.
    server.set_time_mode(ServerTimeMode::RealClock);
    let mut restored = false;
    for _ in 0..60 {
        if client.is_available() {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        restored,
        "granting TIME again must restore availability through the background checker"
    );

    let _ = server.shutdown.send(());
}

/// The scope survives into recovery: a client that reads no server clock sends
/// no `TIME` there either, and recovers on reachability alone.
///
/// The sibling of the finding above. Requiring the clock of every recovery
/// probe would take a replay or cache deployment on a restrictive ACL out of
/// service over a command it never sends — the same mistake, moved from the
/// connect path into the background task.
#[tokio::test]
async fn background_recovery_never_probes_the_clock_for_a_clockless_client() {
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        time_mode: ServerTimeMode::Denied,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let mut config = keyspace_config(server.port);
    config.health_check_interval_seconds = 1;
    config.pool_size = 1;
    let client = RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed");

    // Enter the state an outage produces and let the real checker run.
    client.mark_unavailable_for_test();
    assert!(client.health_checker_started_for_test());

    let mut restored = false;
    for _ in 0..60 {
        if client.is_available() {
            restored = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        restored,
        "a consumer that reads no clock recovers on PING and the topology screen alone"
    );
    assert_eq!(
        server.clock_probes(),
        0,
        "a NotUsed client must spend no round trip on TIME anywhere: an ACL that \
         withholds +time must not take a replay or cache deployment out of service"
    );

    let _ = server.shutdown.send(());
}

/// Starved offset learning does NOT by itself degrade through the failure
/// policy — and this is where the real boundary is.
///
/// Review finding (MINOR 2): the earlier wording said a store whose replies are
/// never prompt is "already past the settlement rollover threshold", so its
/// decisions are going through `redis_failure_policy` anyway. They are not.
/// Response delay and execution delay are different failures, and only one of
/// them rolls a ladder over. The whole boundary, on one fixture:
///
/// 1. Every transaction EXECUTES inside the sub-bucket it was keyed to and
///    answers 200ms later — more than three sub-buckets of a one-second window.
///    Learning stops (no reply is prompt enough to move the offset) and every
///    charge still settles, because settlement is judged on the `TIME` that same
///    transaction carried. No rebuild, no hand-back, no refusal, indefinitely.
/// 2. The server's clock then steps ten minutes ahead under the live client.
///    The frozen base cannot learn it, so every request mis-settles on its
///    FIRST pass and hands its charge back — and the rebuild cannot recover the
///    step either, because the SAME held response is what makes it unrecoverable:
///    the rebuilt pass selects from the server instant the abandoned pass
///    carried, which the 200ms hold already leaves more than three sub-buckets
///    behind the instant the server applies the rebuild in. So the second pass
///    mis-settles too and the request refuses through `redis_failure_policy`.
///
/// That is the whole statement, and it is an entailment rather than a
/// coincidence of these parameters: the threshold that starves learning (a
/// reply latency of one sub-bucket) and the staleness the rebuild inherits are
/// the same quantity, so a response held far enough past one sub-bucket to
/// freeze the base is also far enough to push the rebuilt pass past `b + 1`.
/// A frozen offset plus a drift past the band is an unavailable store, not a
/// permanent double charge.
/// [`a_prompt_store_pays_exactly_one_rebuild_for_a_clock_step_and_learns_it`]
/// is the other side: with prompt replies the same drift costs exactly one
/// rebuild, is admitted, and is learned from that pass's own sample.
#[tokio::test]
async fn starved_offset_learning_settles_until_the_server_clock_drifts_under_it() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    const DRIFT: Duration = Duration::from_secs(600);
    // Held AFTER applying: the server executes promptly and only the response
    // is late. 200ms is more than three sub-buckets of a one-second window and
    // still inside the 500ms screened per-command response deadline.
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(200),
        delayed_charges: usize::MAX,
        hold_phase: HoldPhase::AfterApply,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let client = Arc::new(keyspace_client(server.port));
    // EVERY pooled slot is established (and screened, and probed) up front, on
    // the undrifted clock. A slot opened after the step below would seed the
    // new clock from its own probe and there would be no drift left to observe
    // — including one opened by a detached hand-back racing its rebuild.
    assert_eq!(
        client.warm_pool_for_test().await,
        4,
        "every pooled slot must be screened before the clock moves"
    );

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    // Roomy enough that nothing below is a quota refusal; the assertions are
    // about placement, not about the budget.
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 100,
        duration: Duration::from_secs(1),
    }]);

    // 1. Learning is starved and every decision still stands.
    for _ in 0..6 {
        assert!(
            algorithm
                .check_redis(&client, "ip:127.0.0.1", &op)
                .await
                .expect("a late RESPONSE is not a stale ladder")
                .allowed
        );
    }
    let frozen = client
        .server_clock()
        .offset_nanos()
        .expect("the connections' own probes seeded the offset");
    assert_eq!(
        server.incrs(),
        6,
        "a transaction executed inside its own sub-bucket settles however late \
         its response is: no pass may be abandoned"
    );
    assert_eq!(
        server.decrs(),
        0,
        "and nothing is handed back, so nothing reaches redis_failure_policy"
    );

    // 2. The clock steps under the live client. Nothing can re-teach the offset
    //    while replies stay slow, and nothing can place the rebuild either: the
    //    rebuilt pass selects from the instant the abandoned pass carried, and
    //    this fixture holds every response 200ms AFTER applying it, so by the
    //    time the server applies the rebuild that instant is more than three
    //    sub-buckets stale. Both passes mis-settle and the request refuses.
    //    Repeated, because the point is that it is the steady state and not a
    //    transient.
    server.set_time_mode(ServerTimeMode::Ahead(DRIFT));
    for round in 0..2 {
        let charges_before = server.incrs();
        let handbacks_before = server.decrs();
        let refused = algorithm.check_redis(&client, "ip:127.0.0.1", &op).await;
        assert!(
            refused.is_err(),
            "round {round}: a drift past the settlement band, on a store no reply \
             of which is prompt enough to teach it, must refuse through \
             redis_failure_policy rather than publish a decision from a ladder it \
             could not place: {refused:?}"
        );
        await_compensations(&client).await;
        assert_eq!(
            server.incrs() - charges_before,
            2,
            "round {round}: the bounded rebuild still stops at two transactions"
        );
        assert_eq!(
            server.decrs() - handbacks_before,
            2,
            "round {round}: both abandoned passes hand their charges back"
        );
    }
    let still_frozen = client
        .server_clock()
        .offset_nanos()
        .expect("the offset is still known");
    assert_eq!(
        still_frozen, frozen,
        "no reply was prompt enough to teach the ten-minute step, so the base \
         stays exactly where the probes left it: frozen={frozen} now={still_frozen}"
    );
    // And it is a PLACEMENT refusal, not an endpoint verdict: every transaction
    // succeeded, so the store is still available and the consumer's
    // `redis_failure_policy` is what governs these decisions.
    assert!(
        client.is_available(),
        "a ladder that could not be placed is routed through redis_failure_policy; \
         it must not mark an endpoint that answered every command unusable"
    );

    let _ = server.shutdown.send(());
}

/// The other side of that boundary: with PROMPT replies the same ten-minute
/// step costs exactly ONE rebuild, is admitted, and is not paid twice.
///
/// Nothing is held here, so the sample the mis-settled pass carries is prompt
/// enough to move the base (`clock_sample_is_prompt`'s rule). Three things
/// follow, and they are the exact complement of the starved fixture above:
/// the rebuild selects from an instant that is still current when the server
/// applies it, so it settles and the request is admitted; the same sample
/// teaches the step, so the NEXT request settles on its first pass; and the
/// double charge is therefore a one-off rather than a steady state.
///
/// The pool is warmed BEFORE the step so the only thing that can teach the
/// drift is a charge transaction's own reply — a slot opened afterwards would
/// seed the new clock from its own probe and prove nothing about learning.
#[tokio::test]
async fn a_prompt_store_pays_exactly_one_rebuild_for_a_clock_step_and_learns_it() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };

    const DRIFT: Duration = Duration::from_secs(600);
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions::default()).await;
    let client = Arc::new(keyspace_client(server.port));
    assert_eq!(
        client.warm_pool_for_test().await,
        4,
        "every pooled slot must be screened before the clock moves"
    );

    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 100,
        duration: Duration::from_secs(1),
    }]);
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("an undrifted charge settles on its first pass")
            .allowed
    );
    let seeded = client
        .server_clock()
        .offset_nanos()
        .expect("the connections' own probes seeded the offset");
    assert_eq!(server.incrs(), 1);
    assert_eq!(server.decrs(), 0);

    // The step. The first request after it mis-settles on the base it still
    // holds, hands that charge back, and rebuilds from the server instant —
    // which is current here, because no leg of that round trip was held.
    server.set_time_mode(ServerTimeMode::Ahead(DRIFT));
    let charges_before = server.incrs();
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("one rebuild is still a decision")
            .allowed,
        "a prompt store's single mis-settlement rebuilds and admits"
    );
    await_compensations(&client).await;
    assert_eq!(
        server.incrs() - charges_before,
        2,
        "the drifted base mis-settles once and rebuilds once"
    );
    assert_eq!(
        server.decrs(),
        1,
        "the abandoned pass hands its own charge back, and only it"
    );

    // The mis-settled pass's own reply was prompt, so it also taught the step.
    let learned = client
        .server_clock()
        .offset_nanos()
        .expect("the offset is still known");
    assert!(
        learned - seeded > 500_000_000_000,
        "a prompt sample from the mis-settled pass must teach the ten-minute \
         step: seeded={seeded} learned={learned}"
    );

    // Which makes the rebuild a one-off rather than a standing cost.
    let charges_before = server.incrs();
    let handbacks_before = server.decrs();
    assert!(
        algorithm
            .check_redis(&client, "ip:127.0.0.1", &op)
            .await
            .expect("the relearned base settles on its first pass")
            .allowed
    );
    await_compensations(&client).await;
    assert_eq!(
        server.incrs() - charges_before,
        1,
        "a base that learned the step charges exactly one transaction again"
    );
    assert_eq!(
        server.decrs() - handbacks_before,
        0,
        "with nothing left to hand back"
    );

    let _ = server.shutdown.send(());
}

/// The rule itself: a sample is adopted only while its own reply latency is
/// under one sub-bucket of the narrowest window the transaction charged.
#[test]
fn a_clock_sample_is_prompt_only_inside_one_sub_bucket_of_the_tightest_window() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{
        clock_sample_is_prompt, redis_sub_bucket_nanos,
    };

    // One-second window: 62.5ms sub-buckets.
    assert!(clock_sample_is_prompt(Duration::from_millis(10), 1));
    assert!(clock_sample_is_prompt(Duration::from_micros(62_499), 1));
    assert!(!clock_sample_is_prompt(Duration::from_micros(62_500), 1));
    assert!(!clock_sample_is_prompt(Duration::from_millis(250), 1));

    // A one-minute window tolerates a far later reply, and the boundary is
    // exactly the production sub-bucket width.
    let minute = Duration::from_nanos(redis_sub_bucket_nanos(60) as u64);
    assert_eq!(minute, Duration::from_millis(3_750));
    assert!(clock_sample_is_prompt(
        minute.saturating_sub(Duration::from_nanos(1)),
        60
    ));
    assert!(!clock_sample_is_prompt(minute, 60));

    // A zero window clamps to one second rather than dividing by zero.
    assert!(clock_sample_is_prompt(Duration::from_millis(10), 0));
    assert!(!clock_sample_is_prompt(Duration::from_millis(100), 0));
}

/// Design pins for the shared bucket clock.
///
/// `TIME` rides inside the charge transaction and nowhere else, it is queued
/// unconditionally because a connection that could not answer the standalone
/// probe is never published, the offset only moves on a prompt reply, and the
/// compensation stays a pure `DECR`/`EXPIRE` pair.
#[test]
fn the_server_clock_rides_inside_the_charge_transaction_and_is_probed_first() {
    let redis = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");

    fn method_body<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} must exist"));
        let rest = &source[start..];
        let end = rest[1..]
            .find("\n    /// ")
            .map(|index| index + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    let charge = method_body(redis, "pub async fn charge_rate_limit_windows(");
    assert!(
        charge.contains("pipeline.cmd(\"TIME\");"),
        "every charge transaction must carry the server clock"
    );
    assert!(
        !charge.contains("server_time_permitted"),
        "there is no clock MODE any more: a connection that cannot answer TIME is \
         never published, so nothing may branch on a per-client verdict"
    );
    assert!(
        charge.contains("windows.len() * values_per_window + 1"),
        "the expected reply length must account for the one TIME element exactly"
    );
    assert!(
        charge.contains("clock_sample_is_prompt(reply_latency, narrowest_window_seconds)"),
        "a reply held past one sub-bucket of the tightest charged window must not \
         move the learned offset"
    );
    assert!(
        charge.contains("self.server_clock.record_reply(server_time, local_at_reply)"),
        "a prompt EXEC must still refresh the offset the NEXT request selects with"
    );
    assert!(
        charge.contains("settled_at: Some(server_time)"),
        "settlement is always judged on the instant the SERVER applied the charge"
    );

    let compensate = method_body(redis, "pub async fn uncharge_rate_limit_windows(");
    assert!(
        !compensate.contains("TIME"),
        "a hand-back settles nothing and must not carry the server clock"
    );

    // The probe is STANDALONE and runs on every screened connection, before the
    // socket may carry a policy command.
    let screen = method_body(
        redis,
        "async fn screen_and_arm(&self, conn: &mut redis::aio::MultiplexedConnection) -> bool {",
    );
    assert!(
        screen.contains("self.probe_server_time(conn).await"),
        "every established connection must re-probe TIME; an ACL can change under \
         a live gateway"
    );
    assert!(
        !screen.contains("self.probe_server_time(conn).await;"),
        "the probe's verdict must GATE the connection, not be discarded: a probe \
         that could not be read leaves the socket unscreened"
    );
    let probe = method_body(redis, "async fn probe_server_time(");
    assert!(
        probe.contains("screen_connection_server_clock(conn, SCREENED_COMMAND_RESPONSE_TIMEOUT)"),
        "the connect-path probe must go through the ONE shared screen, bounded by the \
         per-command deadline armed on the connection it just screened: {probe}"
    );

    // The wire work itself is that one shared screen, so the connect path and
    // the background recovery checker cannot drift apart.
    let clock_screen = redis
        .split("async fn screen_connection_server_clock(")
        .nth(1)
        .expect("the shared TIME screen must exist")
        .split("\n/// ")
        .next()
        .expect("the body ends before the next item's doc comment");
    assert!(
        clock_screen.contains("redis::cmd(\"TIME\").query_async::<redis::Value>(conn)"),
        "the screen must be a plain standalone TIME, never a trial run inside MULTI"
    );
    assert!(
        clock_screen.contains("tokio::time::timeout(") && clock_screen.contains("probe_timeout"),
        "an endpoint that accepts and then never answers TIME must cost one bounded \
         probe, not a wedged caller: {clock_screen}"
    );
    assert!(
        clock_screen.contains("parse_redis_server_time(value)"),
        "one parser decides what counts as a clock"
    );
    // EVERY unsuccessful arm rejects the connection. The two recognised
    // refusals pick the diagnostic, never the outcome.
    assert!(
        clock_screen.contains("is_permission_denied_error(&error)")
            && clock_screen.contains("is_unknown_command_error(&error)"),
        "a NOPERM and an unknown command still name themselves in the diagnostic"
    );
    assert_eq!(
        probe.matches("self.reject_unclocked_connection(").count(),
        3,
        "a non-clock reply, a NOPERM, and an unknown command each publish their own \
         diagnostic and reject the connection: {probe}"
    );
    assert_eq!(
        probe.matches("self.mark_unavailable()").count(),
        3,
        "those same three arms must mark the store unavailable themselves — they are \
         not ordinary command failures: {probe}"
    );
    assert!(
        probe.contains("self.note_command_failure(&e)"),
        "a timeout or a transport failure must reach ordinary availability handling"
    );
    assert_eq!(
        probe.matches("true").count(),
        1,
        "only a well-formed clock may publish the connection: {probe}"
    );
    // Recovery publishes THIS client's availability, so it must screen what the
    // client's own connections screen. A PING/topology-only recovery advertised
    // a restored quota store — and logged one — on an endpoint that still
    // denied the clock (review finding MINOR 1).
    let recovery = method_body(redis, "pub(crate) fn start_health_checker_if_needed(");
    assert!(
        recovery.contains("let requires_server_clock = self.requires_server_clock();"),
        "the recovery task must carry the client's clock requirement: {recovery}"
    );
    assert!(
        recovery.contains("if requires_server_clock {")
            && recovery.contains("screen_connection_server_clock(&mut conn, connect_timeout)"),
        "a Required client's recovery must obtain a bounded, well-formed TIME before \
         availability may be republished, through the same screen the probe uses"
    );
    assert!(
        !recovery.contains("record_reply"),
        "a recovery sample is bounded only by the connect timeout, far past one \
         sub-bucket: it must never move the learned offset"
    );

    assert!(
        !redis.contains("fn degrade_to_local_clock")
            && !redis.contains("fn begin_clock_quarantine")
            && !redis.contains("fn quarantine_clock_base_change")
            && !redis.contains("fn observe_window"),
        "local-clock mode and its base-transition machinery are retired; do not \
         reintroduce a second bucket base"
    );

    // Only the replay logger may describe a rejected probe to a replay client,
    // and the raw backend error reaches an operational client only.
    let reject = method_body(redis, "fn reject_unclocked_connection(");
    assert!(
        reject.contains("warn_replay_backend(")
            && !reject.contains("error = %e")
            && !reject.contains("error = %error"),
        "replay clients publish a fixed classification beside the redacted endpoint, \
         never backend text: {reject}"
    );

    // Bucket selection everywhere in production goes through the correction.
    let limiter = include_str!("../../../src/plugins/utils/rate_limit.rs");
    let admission = limiter
        .split("async fn check_http_windows_redis(")
        .nth(1)
        .expect("check_http_windows_redis must exist")
        .split("\n#[cfg(test)]")
        .next()
        .expect("function body ends before the test-only items");
    assert_eq!(
        admission.matches("redis.server_clock()").count(),
        1,
        "selection is the ONLY bucket-clock read on the quota path: settlement now \
         always uses the instant the transaction itself returned"
    );

    // The requirement is scoped at BOTH ends, and the two must stay paired: a
    // probe that only screened, or a charge that only asserted, would let a
    // clockless client select sub-buckets on its own wall clock.
    assert!(
        screen.contains("if !self.requires_server_clock() {"),
        "only a request-quota client's connections may spend a round trip proving \
         TIME: {screen}"
    );
    assert!(
        charge.contains("if !self.requires_server_clock() {"),
        "the ladder must fail closed on a client that never declared the \
         server-clock requirement: {charge}"
    );
    assert!(
        charge.contains("debug_assert!("),
        "and it must say so loudly in debug, where reaching it is a wiring bug: \
         {charge}"
    );
    assert!(
        redis.contains("enum ServerClockRequirement"),
        "the requirement is a construction-time property, not a runtime guess"
    );

    // The limiter picks the client kind from the ALGORITHM, so a new algorithm
    // cannot silently inherit a quota client's ACL demand.
    assert!(
        limiter.contains("if A::REQUIRES_SERVER_CLOCK {")
            && limiter.contains("RedisRateLimitClient::for_request_quota("),
        "RedisLimiter must choose its client from the algorithm's declared contract"
    );
    assert!(
        limiter.contains("const REQUIRES_SERVER_CLOCK: bool;"),
        "the contract must stay a REQUIRED associated const: a default would let a \
         new algorithm decide an operator's Redis ACL by omission"
    );
}

/// The six Redis-backed rate-limit roots, and which of them makes `+time`
/// mandatory.
///
/// Only the three request-quota roots charge the shared sub-bucket ladder. The
/// token, frame, and datagram budgets index their windows locally, so an ACL
/// that withholds `TIME` must leave them enforcing. A new root added without a
/// row here fails the count assertion rather than quietly inheriting either
/// answer.
#[test]
fn only_the_request_quota_roots_make_the_server_clock_mandatory() {
    use ferrum_edge::_test_support::rate_limit_redis_requires_server_clock;

    let redis_fields = |extra: serde_json::Value| {
        let mut base = json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
            "redis_health_check_interval_seconds": 3600,
        });
        let (Some(object), Some(extra)) = (base.as_object_mut(), extra.as_object()) else {
            return base;
        };
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
        base
    };

    let expected = [
        (
            "rate_limiting",
            redis_fields(json!({
                "limit_by": "ip",
                "limits": [{ "scope": "default", "requests_per_minute": 10 }]
            })),
            true,
        ),
        (
            "graphql",
            redis_fields(json!({
                "type_rate_limits": { "query": { "max_requests": 5, "window_seconds": 60 } }
            })),
            true,
        ),
        (
            "grpc_method_router",
            redis_fields(json!({
                "method_rate_limits": {
                    "/pkg.Svc/M": { "max_requests": 5, "window_seconds": 60 }
                }
            })),
            true,
        ),
        (
            "ai_rate_limiter",
            redis_fields(json!({ "token_limit": 100, "window_seconds": 60 })),
            false,
        ),
        (
            "ws_rate_limiting",
            redis_fields(json!({ "frames_per_second": 10, "burst_size": 10 })),
            false,
        ),
        (
            "udp_rate_limiting",
            redis_fields(json!({ "datagrams_per_second": 10 })),
            false,
        ),
    ];

    assert_eq!(
        expected.len(),
        6,
        "every Redis-backed rate-limit root must state which clock contract it is on"
    );
    for (plugin_name, config, requires_clock) in expected {
        let observed = rate_limit_redis_requires_server_clock(plugin_name, &config)
            .unwrap_or_else(|error| panic!("{plugin_name}: {error}"))
            .unwrap_or_else(|| panic!("{plugin_name}: sync_mode redis must build a client"));
        assert_eq!(
            observed, requires_clock,
            "{plugin_name}: server-clock requirement (and therefore whether the \
             deployment's Redis ACL must grant +time)"
        );
    }
}

/// Review finding 3: a capacity refusal taken during a per-decision fallback
/// must still be attributed to the fallback budget.
///
/// A second sub-bucket rollover refuses through `redis_failure_policy` while
/// every transaction it issued SUCCEEDED, so the client's availability signal
/// stays true. Reconstructing the attribution from "is the store unreachable
/// now" therefore answers `false`, and the `429` a previously unseen identity
/// gets at the local key cap loses both its `ratelimit_local_fallback` metadata
/// and its fallback-decision counter — exactly where degraded enforcement is
/// least visible. The decision carries its own provenance instead.
#[tokio::test]
async fn a_second_rollover_attributes_its_capacity_refusal_to_the_fallback_budget() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitWindowSpec,
        RedisFailurePolicy,
    };

    // Every charge stalls past its sub-bucket, so both passes roll over and the
    // decision fails closed into `redis_failure_policy`.
    let server = spawn_keyspace_redis_server(KeyspaceServerOptions {
        charge_delay: Duration::from_millis(250),
        delayed_charges: usize::MAX,
        hold_phase: HoldPhase::BeforeApply,
        ..KeyspaceServerOptions::default()
    })
    .await;
    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": format!("redis://127.0.0.1:{}/0", server.port),
                "redis_pool_size": 4,
                "redis_failure_policy": "local_fallback",
                "redis_health_check_interval_seconds": 3600,
            }),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    assert_eq!(
        backend.redis_failure_policy(),
        Some(RedisFailurePolicy::LocalFallback),
        "this coverage is about the fallback budget, not a fail-closed refusal"
    );
    let client = backend
        .redis_client_arc_for_test()
        .expect("failover backend must own a Redis client");
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 5,
        duration: Duration::from_secs(1),
    }]);

    // One local slot, and the first identity takes it on the fallback budget.
    let seen = backend
        .check_with_redis_key_and_local_capacity_attributed(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1,
        )
        .await;
    assert!(
        seen.outcome.expect("an admitted fallback decision").allowed,
        "the per-process budget admits the first identity"
    );
    assert!(
        seen.local_fallback,
        "a rollover refusal routes THIS decision onto the fallback budget"
    );

    // The signal the old attribution read: the client is perfectly healthy,
    // because both of its transactions succeeded.
    assert!(
        client.is_available(),
        "a rollover is not a command failure; the endpoint is reachable"
    );
    assert!(
        !backend.local_fallback_active(),
        "the backend-level outage question answers 'no', which is why a \
         capacity refusal must not be attributed from it"
    );

    // A previously unseen identity at the cap: no outcome to carry the marker.
    let denied = backend
        .check_with_redis_key_and_local_capacity_attributed(
            "identity-b".to_string(),
            || "{ferrum%3Atest:identity-b}".to_string(),
            &op,
            1,
        )
        .await;
    assert!(
        denied.outcome.is_none(),
        "an unseen identity at the local cap is a capacity refusal"
    );
    assert!(
        denied.local_fallback,
        "the capacity 429 belongs to the fallback budget and must stay attributed"
    );
    assert_eq!(backend.tracked_keys_count(), 1);

    let _ = server.shutdown.send(());
}

// ── Redis health-task lifecycle (issue #2305) ─────────────────────────────

#[tokio::test(start_paused = true)]
async fn redis_health_checker_stops_after_client_drop() {
    let (port, shutdown, accepts) = spawn_delayed_redis_handshake_server(None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.health_check_interval_seconds = 1;
    config.connect_timeout_seconds = 1;

    let client = redis_rate_limit_client_for_test(config);
    client.mark_unavailable_for_test();
    assert!(client.health_checker_started_for_test());
    let abort = client
        .health_checker_abort_for_test()
        .expect("health checker abort handle");

    // The checker is spawned asynchronously, so its first sleep may arm after
    // an initial clock advance. Advance whole virtual intervals (not arbitrary
    // wall-clock sleeps) until the mock server observes the real dial.
    for _ in 0..3 {
        tokio::time::advance(Duration::from_secs(1)).await;
        for _ in 0..100 {
            if accepts.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        if accepts.load(Ordering::Relaxed) >= 1 {
            break;
        }
    }
    let after_first = accepts.load(Ordering::Relaxed);
    assert!(
        after_first >= 1,
        "health checker must dial at least once after the first interval"
    );

    drop(client);
    for _ in 0..10 {
        if abort.is_finished() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(abort.is_finished(), "drop must abort the health checker");

    let baseline_accepts = accepts.load(Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(5)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        baseline_accepts,
        "retired client must not keep dialing Redis after drop"
    );

    let _ = shutdown.send(());
}

#[tokio::test(start_paused = true)]
async fn failover_observer_drop_releases_client_and_stops_task() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };
    use std::sync::Arc;

    let http = PluginHttpClient::default();
    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:9/0",
                "redis_health_check_interval_seconds": 1,
            }),
            &http,
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");

    let client = backend
        .redis_client_arc_for_test()
        .expect("redis client arc");
    let weak = Arc::downgrade(&client);
    let observer = backend
        .health_observer_abort_for_test()
        .expect("observer abort");
    // Backend + local clone: observer must NOT hold an extra strong Arc.
    assert_eq!(Arc::strong_count(&client), 2);
    drop(client);

    drop(backend);
    for _ in 0..20 {
        if observer.is_finished() && weak.strong_count() == 0 {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert!(
        observer.is_finished(),
        "drop must abort the failover observer"
    );
    assert_eq!(
        weak.strong_count(),
        0,
        "dropping the limiter must release Redis client ownership"
    );
    assert!(
        weak.upgrade().is_none(),
        "retired Redis client must be fully released"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_failover_replacement_leaves_only_active_observer() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, RateLimitBackend,
    };

    let http = PluginHttpClient::default();
    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    let mut retired_observers = Vec::new();
    let mut active: Option<RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>> = None;

    for generation in 0..5 {
        let next: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
            RateLimitBackend::from_plugin_config(
                // Shared path used by rate_limiting / graphql / grpc_method_router.
                match generation % 3 {
                    0 => "rate_limiting",
                    1 => "graphql",
                    _ => "grpc_method_router",
                },
                &json!({
                    "sync_mode": "redis",
                    "redis_url": format!("redis://127.0.0.1:{}/0", 9000 + generation),
                    "redis_key_prefix": format!("gen:{generation}"),
                    "redis_health_check_interval_seconds": 1,
                }),
                &http,
                algorithm,
            )
            .expect("failover backend");
        let next_abort = next
            .health_observer_abort_for_test()
            .expect("active observer");
        if let Some(prev) = active.replace(next) {
            let prev_abort = prev
                .health_observer_abort_for_test()
                .expect("retired observer");
            drop(prev);
            retired_observers.push(prev_abort);
        }
        assert!(!next_abort.is_finished());
    }

    for _ in 0..30 {
        if retired_observers.iter().all(|a| a.is_finished()) {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(1)).await;
    }
    assert!(
        retired_observers.iter().all(|a| a.is_finished()),
        "every retired generation observer must stop"
    );
    let active_abort = active
        .as_ref()
        .and_then(|b| b.health_observer_abort_for_test())
        .expect("active generation");
    assert!(
        !active_abort.is_finished(),
        "only the active generation observer may remain"
    );
}

// ── WATCH fencing connection type + fail-closed disconnect (GHSA-f72h) ────

/// Static pin: ownership CAS helpers must dial a non-reconnecting
/// `MultiplexedConnection`, never a transparently-reconnecting
/// `ConnectionManager` that can drop WATCH state across a reconnect.
#[test]
fn watch_transaction_path_pins_multiplexed_connection_not_connection_manager() {
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    assert!(
        source.contains(
            "async fn get_dedicated_connection(&self) -> Option<redis::aio::MultiplexedConnection>"
        ),
        "get_dedicated_connection must return MultiplexedConnection"
    );
    assert!(
        !source.contains(
            "async fn get_dedicated_connection(&self) -> Option<redis::aio::ConnectionManager>"
        ),
        "get_dedicated_connection must not return ConnectionManager"
    );
    assert!(
        source.contains("client.get_multiplexed_async_connection_with_config"),
        "dedicated path must dial MultiplexedConnection directly"
    );

    let type_name = RedisRateLimitClient::dedicated_watch_connection_type_name_for_test();
    assert_eq!(
        type_name,
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    );
    assert!(
        !type_name.contains("ConnectionManager"),
        "WATCH helper type must not be ConnectionManager: {type_name}"
    );

    for marker in [
        "pub async fn delete_if_value_matches",
        "pub async fn set_bytes_with_expire_if_value_matches",
    ] {
        let start = source
            .find(marker)
            .unwrap_or_else(|| panic!("missing helper {marker}"));
        let rest = &source[start..];
        let end = rest[1..]
            .find("\n    pub async fn ")
            .map(|i| i + 1)
            .unwrap_or(rest.len().min(12_000));
        let body = &rest[..end];
        assert!(
            body.contains("get_dedicated_connection()"),
            "{marker} must use get_dedicated_connection"
        );
        let brace = body
            .find('{')
            .unwrap_or_else(|| panic!("{marker} missing body"));
        let impl_body = &body[brace..];
        assert!(
            !impl_body.contains("get_connection()"),
            "{marker} must not use the shared pooled connection path"
        );
        assert!(
            !impl_body.contains("ConnectionManager"),
            "{marker} implementation must not reference ConnectionManager"
        );
        // Mismatch path + GET-error path must both attempt UNWATCH (fail closed).
        assert!(
            impl_body.matches("UNWATCH").count() >= 2,
            "{marker} must UNWATCH on pre-MULTI mismatch and GET failure"
        );
    }
}

/// Accept TCP, complete the redis-rs handshake with +OK replies, answer the
/// first WATCH with +OK, then drop the socket before GET/EXEC. Counts SET/DEL
/// payloads so a fail-open unconditional write would be observable.
async fn spawn_watch_then_drop_redis_server() -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let writes = Arc::new(AtomicUsize::new(0));
    let writes_task = Arc::clone(&writes);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    let writes = Arc::clone(&writes_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending = Vec::new();
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            if pending
                                .windows(b"$3\r\nSET\r\n".len())
                                .any(|w| w == b"$3\r\nSET\r\n")
                                || pending
                                    .windows(b"$3\r\nDEL\r\n".len())
                                    .any(|w| w == b"$3\r\nDEL\r\n")
                            {
                                writes.fetch_add(1, Ordering::Relaxed);
                            }
                            if pending
                                .windows(b"$5\r\nWATCH\r\n".len())
                                .any(|w| w == b"$5\r\nWATCH\r\n")
                            {
                                let _ = stream.write_all(b"+OK\r\n").await;
                                // Drop after acknowledging WATCH so GET/EXEC
                                // observe a dead socket with no watch state.
                                break;
                            }
                            let commands =
                                pending.iter().filter(|&&b| b == b'*').count().max(1);
                            let mut reply = Vec::new();
                            if chunk_contains(&pending, TIME_CMD) {
                                // The standalone screening probe. `+OK` here is
                                // not a clock, so the connection would never be
                                // published and the WATCH sequence under test
                                // would never run.
                                reply.extend_from_slice(&host_clock_time_reply());
                            } else {
                                for _ in 0..commands {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                            pending.clear();
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, writes)
}

#[tokio::test]
async fn watch_cas_helpers_fail_closed_when_connection_drops_after_watch() {
    let (port, shutdown, writes) = spawn_watch_then_drop_redis_server().await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 60;
    let client = redis_rate_limit_client_for_test(config);

    let set_result = client
        .set_bytes_with_expire_if_value_matches("fence-key", b"expected", b"stale", 60)
        .await;
    assert!(
        set_result.is_err(),
        "disconnect after WATCH must fail closed, got {set_result:?}"
    );

    let delete_result = client
        .delete_if_value_matches("fence-key", b"expected")
        .await;
    assert!(
        delete_result.is_err(),
        "disconnect after WATCH must fail closed on delete, got {delete_result:?}"
    );

    assert_eq!(
        writes.load(Ordering::Relaxed),
        0,
        "a dropped WATCH sequence must not publish SET/DEL"
    );
    assert!(
        !client.is_available(),
        "I/O failure must mark Redis unavailable"
    );
    // Only the dedicated (WATCH/MULTI) connection path ran here, and its
    // success arm does not arm the recovery checker. Marking unavailable must
    // therefore arm it itself, or a client that only ever uses dedicated
    // connections stays unavailable until the next config reload.
    assert!(
        client.health_checker_started_for_test(),
        "a dedicated command failure must arm recovery instead of pinning fail-closed consumers \
         unavailable until reload"
    );

    let _ = shutdown.send(());
}

/// Complete the redis-rs handshake with `+OK` replies, then drop the socket the
/// moment a `SET` arrives. This produces a genuine *command* error on the
/// cached connection-manager path (not a connect error), which is the only way
/// `set_bytes_nx_with_expire` reaches its own `mark_unavailable()`.
async fn spawn_set_then_drop_redis_server() -> (u16, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    tokio::spawn(async move {
                        let mut buf = vec![0_u8; 16 * 1024];
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            if buf[..n]
                                .windows(b"$3\r\nSET\r\n".len())
                                .any(|w| w == b"$3\r\nSET\r\n")
                            {
                                // Hang up mid-command: the claim must fail
                                // closed rather than be reported as won.
                                break;
                            }
                            let commands = buf[..n].iter().filter(|&&b| b == b'*').count().max(1);
                            let mut reply = Vec::new();
                            if chunk_contains(&buf[..n], TIME_CMD) {
                                // The standalone screening probe: without a
                                // clock the connection is dropped unpublished
                                // and the `SET` under test never arrives.
                                reply.extend_from_slice(&host_clock_time_reply());
                            } else {
                                for _ in 0..commands {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx)
}

/// Fail-closed consumers (`soap_ws_security` with `nonce.replay_scope: shared`,
/// `request_deduplication`) gate every future claim on `is_available()` and
/// *reject* traffic while it is false. A transient command error on
/// `set_bytes_nx_with_expire` must fail the claim closed and mark Redis
/// unavailable.
///
/// Recovery-checker arming from a demonstrably *not-started* state is covered
/// by `watch_cas_helpers_fail_closed_when_connection_drops_after_watch` (and by
/// hostname egress-denial coverage below): this claim primitive uses the cached
/// `ConnectionManager` path, whose successful connect already starts the
/// checker, so asserting the flag here would not prove the unavailable
/// transition itself.
#[tokio::test]
async fn a_command_error_on_the_claim_primitive_fails_closed_and_marks_unavailable() {
    let (port, shutdown) = spawn_set_then_drop_redis_server().await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 3600;
    let client = redis_rate_limit_client_for_test(config);

    let claimed = client
        .set_bytes_nx_with_expire("claim-key", b"marker", 60)
        .await;
    assert!(
        claimed.is_err(),
        "a mid-command disconnect must fail the claim closed, got {claimed:?}"
    );
    assert!(
        !client.is_available(),
        "a failed claim must mark Redis unavailable"
    );

    let _ = shutdown.send(());
}

/// A hostname that currently resolves to an egress-denied address must arm the
/// recovery checker: DNS answers can change, and fail-closed consumers would
/// otherwise stay unavailable until the next config reload. This path never
/// establishes a cached connection, so the checker was not started beforehand.
#[tokio::test]
async fn hostname_egress_denial_arms_the_recovery_checker() {
    use ferrum_edge::config::BackendAllowIps;
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use std::collections::HashMap;

    let mut overrides = HashMap::new();
    overrides.insert("redis.denied.test".to_string(), "10.0.0.1".to_string());
    let dns_cache = DnsCache::new(DnsConfig {
        global_overrides: overrides,
        backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
        ..DnsConfig::default()
    });
    let mut config = make_config("redis://redis.denied.test:6379/0", false);
    config.health_check_interval_seconds = 3600;
    let client = RedisRateLimitClient::new(config, Some(dns_cache), false, None)
        .expect("construction without a CA path must succeed");

    assert!(
        !client.health_checker_started_for_test(),
        "precondition: checker must not already be running"
    );
    assert!(
        !client.connect_cached_for_test().await,
        "hostname egress denial must fail closed without dialing"
    );
    assert!(!client.is_available());
    assert!(
        client.health_checker_started_for_test(),
        "hostname egress denial must arm recovery so a later DNS answer can restore the client"
    );
    let abort = client
        .health_checker_abort_for_test()
        .expect("recovery checker abort handle");
    assert!(!abort.is_finished());
}

/// A denied literal-IP `redis_url` is static configuration: re-screening the
/// same address stays denied, so the recovery checker must not start.
#[tokio::test]
async fn literal_ip_egress_denial_does_not_arm_the_recovery_checker() {
    use ferrum_edge::config::BackendAllowIps;
    use ferrum_edge::config::BackendEgressPolicy;
    use ferrum_edge::dns::{DnsCache, DnsConfig};

    let dns_cache = DnsCache::new(DnsConfig {
        backend_allow_ips: BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
        ..DnsConfig::default()
    });
    let mut config = make_config("redis://127.0.0.1:6379/0", false);
    config.health_check_interval_seconds = 3600;
    let client = RedisRateLimitClient::new(config, Some(dns_cache), false, None)
        .expect("construction without a CA path must succeed");

    assert!(!client.health_checker_started_for_test());
    assert!(
        !client.connect_cached_for_test().await,
        "literal-IP egress denial must fail closed without dialing"
    );
    assert!(!client.is_available());
    assert!(
        !client.health_checker_started_for_test(),
        "literal-IP egress denial must not arm a recovery checker"
    );
}

/// Validation diagnostics on the shared Redis admission path must name the
/// field/shape without echoing rejected values, URLs, or credential-bearing
/// config objects (request_deduplication reaches this helper).
#[test]
fn redis_config_validation_diagnostics_are_value_redacted() {
    const PASSWORD: &str = "sentinel-redis-password-9f21c8a4";
    const USER: &str = "sentinel-redis-user-6c38";
    const TOKEN: &str = "sentinel-query-token-4a57";

    let leaked_shape = json!(format!(
        "redis://{USER}:{PASSWORD}@cache.internal:6379/0?auth={TOKEN}"
    ));
    let err = RedisConfig::from_plugin_config(&leaked_shape, "ferrum:test")
        .err()
        .unwrap_or_else(|| panic!("non-object config must be rejected"));
    assert!(
        err.contains("must be a JSON object"),
        "unexpected non-object diagnostic: {err}"
    );
    for secret in [PASSWORD, USER, TOKEN, "redis://", "cache.internal"] {
        assert!(
            !err.contains(secret),
            "non-object diagnostic must not echo {secret:?}: {err}"
        );
    }

    let sync_err = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": format!("redis-with-{PASSWORD}"),
            "redis_url": format!("redis://{USER}:{PASSWORD}@cache.internal:6379/0"),
        }),
        "ferrum:test",
    )
    .err()
    .unwrap_or_else(|| panic!("invalid sync_mode must be rejected"));
    assert!(
        sync_err.contains("'sync_mode'") && sync_err.contains("'local' or 'redis'"),
        "unexpected sync_mode diagnostic: {sync_err}"
    );
    for secret in [PASSWORD, USER] {
        assert!(
            !sync_err.contains(secret),
            "sync_mode diagnostic must not echo {secret:?}: {sync_err}"
        );
    }

    let url_err = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": format!(
                "http://{USER}:{PASSWORD}@cache.internal:6379/0?auth={TOKEN}#{PASSWORD}"
            ),
        }),
        "ferrum:test",
    )
    .err()
    .unwrap_or_else(|| panic!("non-redis scheme must be rejected"));
    assert!(
        url_err.contains("'redis_url'") && url_err.contains("scheme"),
        "unexpected url diagnostic: {url_err}"
    );
    for secret in [PASSWORD, USER, TOKEN, "http://", "cache.internal"] {
        assert!(
            !url_err.contains(secret),
            "redis_url diagnostic must not echo {secret:?}: {url_err}"
        );
    }

    let parse_err = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": format!("not a url {USER}:{PASSWORD}?auth={TOKEN}"),
        }),
        "ferrum:test",
    )
    .err()
    .unwrap_or_else(|| panic!("unparseable redis_url must be rejected"));
    assert!(
        parse_err.contains("'redis_url'") && parse_err.contains("valid URL"),
        "unexpected parse diagnostic: {parse_err}"
    );
    for secret in [PASSWORD, USER, TOKEN] {
        assert!(
            !parse_err.contains(secret),
            "parse diagnostic must not echo {secret:?}: {parse_err}"
        );
    }
}

// ── Redis topology screening (GHSA-87rq-v4hx-8rcq) ────────────────────────
//
// The shared client is not Cluster-aware. Pointing an enforcement plugin at a
// Redis Cluster endpoint used to surface only as "Redis is down", which silently
// turned one distributed budget into one budget per gateway process. These
// prove the endpoint is screened proactively (INFO CLUSTER) and reactively
// (Cluster-only error codes), and that the rejection is terminal.

#[test]
fn parse_cluster_enabled_recognizes_only_a_reported_value() {
    use ferrum_edge::_test_support::parse_cluster_enabled;

    assert_eq!(
        parse_cluster_enabled("# Cluster\r\ncluster_enabled:1\r\n"),
        Some(true)
    );
    assert_eq!(
        parse_cluster_enabled("# Cluster\r\ncluster_enabled:0\r\n"),
        Some(false)
    );
    // Any non-zero value counts as enabled.
    assert_eq!(parse_cluster_enabled("cluster_enabled:2"), Some(true));
    // Absent / unparseable stays unknown so RESP-compatible servers that do not
    // report the field are never rejected by the proactive screen.
    assert_eq!(
        parse_cluster_enabled("# Server\r\nredis_version:7.2.4"),
        None
    );
    assert_eq!(parse_cluster_enabled(""), None);
    assert_eq!(parse_cluster_enabled("cluster_enabled:"), None);
    assert_eq!(parse_cluster_enabled("cluster_enabled_extra:1"), None);
}

#[test]
fn classify_memory_info_accepts_unlimited_or_noeviction_only() {
    use ferrum_edge::_test_support::{MemoryPolicyScreen, classify_memory_info};

    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory:0\r\nmaxmemory_policy:allkeys-lru\r\n"),
        MemoryPolicyScreen::Usable
    );
    // Redis INFO MEMORY also emits `maxmemory_human`; that must not clobber the
    // exact `maxmemory` field or an unlimited server looks unproven/unsafe.
    assert_eq!(
        classify_memory_info(
            "# Memory\r\nmaxmemory:0\r\nmaxmemory_human:0B\r\nmaxmemory_policy:allkeys-lru\r\n"
        ),
        MemoryPolicyScreen::Usable
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory:1048576\r\nmaxmemory_policy:noeviction\r\n"),
        MemoryPolicyScreen::Usable
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory_policy:noeviction\r\n"),
        MemoryPolicyScreen::Usable
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory:1\r\nmaxmemory_policy:volatile-lru\r\n"),
        MemoryPolicyScreen::UnsafeEviction
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory:1\r\nmaxmemory_policy:allkeys-lru\r\n"),
        MemoryPolicyScreen::UnsafeEviction
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory_policy:allkeys-random\r\n"),
        MemoryPolicyScreen::UnsafeEviction
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory:1\r\n"),
        MemoryPolicyScreen::Unproven
    );
    assert_eq!(
        classify_memory_info("# Memory\r\nmaxmemory_human:1M\r\n"),
        MemoryPolicyScreen::Unproven
    );
    assert_eq!(classify_memory_info(""), MemoryPolicyScreen::Unproven);
    assert_eq!(
        classify_memory_info("maxmemory:\r\nmaxmemory_policy:\r\n"),
        MemoryPolicyScreen::Unproven
    );
}

/// GHSA-26gf-943w-w5x8: the no-eviction prerequisite is a property of what the
/// consumer retains, not of how it logs. A client whose retained record IS the
/// control must demand the screen; a counter or cache client must not, because
/// eviction only costs it accuracy and requiring `INFO MEMORY` of it would
/// refuse deployments that are perfectly safe.
#[test]
fn only_retention_authorities_require_the_no_eviction_screen() {
    let config = make_config("redis://127.0.0.1:6379/0", false);
    let counters = RedisRateLimitClient::new(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(
        !counters.requires_no_eviction_screen_for_test(),
        "a counter/cache client must keep the topology-only screen"
    );

    let replay = RedisRateLimitClient::for_replay_authority(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(replay.requires_no_eviction_screen_for_test());

    let retention = RedisRateLimitClient::for_retention_authority(config, None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(
        retention.requires_no_eviction_screen_for_test(),
        "an idempotency authority must prove the endpoint retains its records"
    );
}

/// The `TIME` prerequisite belongs to the consumers that select sub-buckets on
/// the Redis server's clock, not to the socket. Screening is shared, so making
/// it a property of the connection took a replay-only deployment on a
/// restrictive ACL out of service for a command it never sends.
#[test]
fn only_request_quota_clients_require_the_server_clock() {
    let config = make_config("redis://127.0.0.1:6379/0", false);

    let quota = RedisRateLimitClient::for_request_quota(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(
        quota.requires_server_clock_for_test(),
        "request-quota admission orders one ladder across gateways on the server clock"
    );

    let counters = RedisRateLimitClient::new(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    let replay = RedisRateLimitClient::for_replay_authority(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    let retention = RedisRateLimitClient::for_retention_authority(config, None, false, None)
        .expect("construction without a CA path must succeed");

    for (label, client) in [
        ("counter/cache", &counters),
        ("replay authority", &replay),
        ("retention authority", &retention),
    ] {
        assert!(
            !client.requires_server_clock_for_test(),
            "{label}: a consumer that reads no clock must not force an operator to grant +time"
        );
    }
}

/// The two screening prerequisites are independent: the retention proof follows
/// what a consumer RETAINS, the clock proof follows what it COMPUTES, and no
/// current consumer needs both.
#[test]
fn the_retention_and_server_clock_prerequisites_are_chosen_independently() {
    let config = make_config("redis://127.0.0.1:6379/0", false);

    let quota = RedisRateLimitClient::for_request_quota(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(quota.requires_server_clock_for_test());
    assert!(
        !quota.requires_no_eviction_screen_for_test(),
        "an evicted counter degrades a budget; it does not void a guarantee"
    );

    let retention = RedisRateLimitClient::for_retention_authority(config, None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(retention.requires_no_eviction_screen_for_test());
    assert!(
        !retention.requires_server_clock_for_test(),
        "an idempotency authority claims markers with SET NX EX and reads no clock"
    );
}

/// The three memory-policy verdicts, applied exactly as a freshly established
/// connection applies them: a proven non-evicting endpoint is usable, a proven
/// evicting one is terminal for the client generation (no recovery ping can
/// make the next operation correct), and an unproven screen is a recoverable
/// outage that leaves the consumer's failure policy in charge.
#[test]
fn retention_authority_admits_only_a_proven_non_evicting_endpoint() {
    use ferrum_edge::_test_support::MemoryPolicyScreen;

    let config = make_config("redis://127.0.0.1:6379/0", false);

    let usable = RedisRateLimitClient::for_retention_authority(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(usable.apply_memory_policy_screen_for_test(MemoryPolicyScreen::Usable));
    assert!(usable.is_available());
    assert!(!usable.is_topology_unsupported());

    let evicting = RedisRateLimitClient::for_retention_authority(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(!evicting.apply_memory_policy_screen_for_test(MemoryPolicyScreen::UnsafeEviction));
    assert!(!evicting.is_available());
    assert!(
        evicting.is_topology_unsupported(),
        "a proven evicting endpoint is configuration, not an outage"
    );
    // Terminal means terminal: a later successful probe cannot republish it.
    assert!(!evicting.publish_reachable_for_test());
    assert!(!evicting.is_available());

    let unproven = RedisRateLimitClient::for_retention_authority(config.clone(), None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(!unproven.apply_memory_policy_screen_for_test(MemoryPolicyScreen::Unproven));
    assert!(!unproven.is_available());
    assert!(
        !unproven.is_topology_unsupported(),
        "an unproven screen must stay recoverable"
    );
    assert!(unproven.publish_reachable_for_test());
    assert!(unproven.is_available());

    // A counter/cache client never runs the screen, so even a proven evicting
    // verdict leaves it usable.
    let counters = RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed");
    assert!(counters.apply_memory_policy_screen_for_test(MemoryPolicyScreen::UnsafeEviction));
    assert!(counters.is_available());
    assert!(!counters.is_topology_unsupported());
}

#[test]
fn cluster_topology_codes_are_terminal_but_outage_codes_are_not() {
    use ferrum_edge::_test_support::is_cluster_topology_code;

    for code in ["MOVED", "ASK", "CROSSSLOT", "CLUSTERDOWN", "TRYAGAIN"] {
        assert!(
            is_cluster_topology_code(Some(code)),
            "{code} proves an unsupported Cluster topology"
        );
    }
    // MASTERDOWN/LOADING are ordinary replication/availability failures and must
    // stay recoverable; None is a transport error, not a topology verdict.
    for code in ["MASTERDOWN", "LOADING", "ERR", "NOAUTH", "WRONGTYPE"] {
        assert!(
            !is_cluster_topology_code(Some(code)),
            "{code} must not permanently disable the endpoint"
        );
    }
    assert!(!is_cluster_topology_code(None));
}

#[test]
fn slot_keys_of_one_rate_key_share_a_hash_tag() {
    use ferrum_edge::_test_support::redis_slot_key;

    let config = || make_config("redis://127.0.0.1:6379/0", false);
    let prev = redis_slot_key(config(), "ip:1.2.3.4", &["41"]);
    let curr = redis_slot_key(config(), "ip:1.2.3.4", &["42"]);
    assert_eq!(prev, "{ferrum%3Atest:ip%3A1.2.3.4}:41");
    assert_eq!(curr, "{ferrum%3Atest:ip%3A1.2.3.4}:42");

    fn hash_tag(key: &str) -> &str {
        let open = key.find('{').expect("hash tag opens");
        let close = key[open + 1..].find('}').expect("hash tag closes") + open + 1;
        &key[open + 1..close]
    }
    assert_eq!(
        hash_tag(&prev),
        hash_tag(&curr),
        "previous and current window buckets must land in one slot"
    );

    // The UDP datagram/byte pair of one client shares a slot too.
    let datagrams = redis_slot_key(config(), "udp:1.2.3.4", &["datagrams", "7"]);
    let bytes = redis_slot_key(config(), "udp:1.2.3.4", &["bytes", "7"]);
    assert_eq!(hash_tag(&datagrams), hash_tag(&bytes));

    // Distinct rate keys still spread across slots — the tag must not collapse
    // an entire policy onto one hot slot.
    let other = redis_slot_key(config(), "ip:5.6.7.8", &["42"]);
    assert_ne!(hash_tag(&curr), hash_tag(&other));

    // Caller-controlled braces cannot terminate the tag early, and delimiters
    // are escaped so distinct prefix/rate-key pairs cannot collapse onto the
    // same logical tag.
    let hostile = redis_slot_key(config(), "identity}:x%y{z", &["42"]);
    assert_eq!(hash_tag(&hostile), "ferrum%3Atest:identity%7D%3Ax%25y%7Bz");
    assert_ne!(hash_tag(&hostile), hash_tag(&curr));
}

/// Parse one complete RESP command array out of `buf`.
///
/// Returns the uppercased command name and the number of bytes it consumed, or
/// `None` when the buffer holds only a partial command. Framing has to be exact:
/// a fake server that guesses reply counts from a read chunk (say, by counting
/// `*` bytes) answers a split or coalesced write with the wrong number of
/// replies, and an extra reply drives the client's multiplexed connection into
/// an internal accounting underflow instead of the behavior under test.
fn parse_resp_command(buf: &[u8]) -> Option<(String, usize)> {
    fn read_line(buf: &[u8], from: usize) -> Option<(&[u8], usize)> {
        let rest = buf.get(from..)?;
        let idx = rest.windows(2).position(|w| w == b"\r\n")?;
        Some((&rest[..idx], from + idx + 2))
    }

    if *buf.first()? != b'*' {
        return None;
    }
    let (count_line, mut cursor) = read_line(buf, 1)?;
    let argc: usize = std::str::from_utf8(count_line).ok()?.parse().ok()?;
    let mut name = None;
    for arg in 0..argc {
        if *buf.get(cursor)? != b'$' {
            return None;
        }
        let (len_line, after_len) = read_line(buf, cursor + 1)?;
        let len: usize = std::str::from_utf8(len_line).ok()?.parse().ok()?;
        let end = after_len.checked_add(len)?;
        let payload = buf.get(after_len..end)?;
        if buf.get(end..end + 2)? != b"\r\n" {
            return None;
        }
        if arg == 0 {
            name = Some(String::from_utf8_lossy(payload).to_uppercase());
        }
        cursor = end + 2;
    }
    Some((name?, cursor))
}

/// Minimal RESP server: replies `+OK` to every command except `INFO`, which gets
/// `info_payload` as a bulk string. Once `after_info_reply` is set, every later
/// command receives that raw reply instead of `+OK` — except `MULTI`, which is
/// still answered `+OK` because that is what a real Cluster node does: it opens
/// the transaction and redirects the keyed commands queued inside it. The
/// standalone `TIME` screening probe gets this host's clock unless
/// `after_info_reply` has claimed it. Counts accepted TCP connections and
/// observed `INCR` commands.
async fn spawn_topology_redis_server(
    info_payload: &'static str,
    after_info_reply: Option<&'static str>,
) -> (u16, oneshot::Sender<()>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let incrs = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let incrs_task = Arc::clone(&incrs);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let incrs = Arc::clone(&incrs_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending: Vec<u8> = Vec::new();
                        let mut info_seen = false;
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            let mut reply = Vec::new();
                            // Exactly one reply per fully received command, so
                            // the client's in-flight accounting always matches.
                            while let Some((name, consumed)) = parse_resp_command(&pending) {
                                pending.drain(..consumed);
                                if name == "INCR" {
                                    incrs.fetch_add(1, Ordering::Relaxed);
                                }
                                if name == "INFO" {
                                    info_seen = true;
                                    reply.extend_from_slice(
                                        format!("${}\r\n{info_payload}\r\n", info_payload.len())
                                            .as_bytes(),
                                    );
                                } else if info_seen
                                    && let Some(raw) = after_info_reply
                                    && name != "MULTI"
                                {
                                    reply.extend_from_slice(raw.as_bytes());
                                } else if name == "TIME" {
                                    // The standalone screening probe, answered
                                    // only where `after_info_reply` has not
                                    // already claimed every post-screen command.
                                    reply.extend_from_slice(&host_clock_time_reply());
                                } else {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if reply.is_empty() {
                                continue;
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, shutdown_tx, accepts, incrs)
}

/// A Cluster endpoint must be refused at connect, before it can serve a single
/// policy operation, and must never be redialed by the recovery checker.
#[tokio::test]
async fn cluster_enabled_endpoint_is_refused_before_serving_policy_operations() {
    let (port, shutdown, accepts, incrs) =
        spawn_topology_redis_server("# Cluster\r\ncluster_enabled:1\r\n", None).await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 3600;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    let first = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(first.is_err(), "a Cluster endpoint must not serve counters");
    assert!(
        client.is_topology_unsupported(),
        "cluster_enabled:1 must be recorded as an unsupported topology"
    );
    assert!(!client.is_available(), "topology rejection is terminal");
    assert_eq!(
        incrs.load(Ordering::Relaxed),
        0,
        "no counter command may reach a Cluster endpoint"
    );

    let dials_after_first = accepts.load(Ordering::Relaxed);
    let second = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(second.is_err());
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        dials_after_first,
        "a rejected topology must never be redialed"
    );

    let _ = shutdown.send(());
}

/// A server that hides its topology from `INFO` is still caught the first time
/// it answers with a Cluster-only redirection.
///
/// The redirection has to be caught through the shape a real Cluster node
/// produces: `incr_with_expire` sends a `MULTI`/`EXEC` transaction, the node
/// accepts `MULTI` and redirects the keyed commands at queue time, and the
/// client surfaces one aborted-transaction error whose *own* code is
/// `EXECABORT` with the `MOVED` replies nested inside it.
#[tokio::test]
async fn cluster_redirection_error_permanently_disables_the_endpoint() {
    let (port, shutdown, accepts, _incrs) = spawn_topology_redis_server(
        "# Cluster\r\ncluster_enabled:0\r\n",
        Some("-MOVED 1234 127.0.0.1:7001\r\n"),
    )
    .await;
    let mut config = make_config(&format!("redis://127.0.0.1:{port}/0"), false);
    config.connect_timeout_seconds = 5;
    config.health_check_interval_seconds = 3600;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    let first = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(
        first.is_err(),
        "a MOVED redirection must fail the operation"
    );
    assert!(
        client.is_topology_unsupported(),
        "MOVED proves the endpoint is a Cluster this client cannot enforce against"
    );
    assert!(!client.is_available());

    let dials = accepts.load(Ordering::Relaxed);
    let second = client.incr_with_expire("{ferrum:test:key}:1", 60).await;
    assert!(second.is_err());
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        dials,
        "topology rejection must stop reconnection attempts"
    );

    let _ = shutdown.send(());
}

// ── Bounded topology screening + terminal rejection under concurrency ──────
//   (GHSA-87rq-v4hx-8rcq)
//
// Two properties the screen has to hold beyond "a Cluster is refused":
//
// 1. The proactive `INFO CLUSTER` probe is bounded by the configured
//    `redis_connect_timeout_seconds`. A server can accept and authenticate a
//    connection and then never answer `INFO`; an unbounded screen would hang
//    the first enforcement operation instead of refusing it. A probe that does
//    not complete is an ordinary outage — never proof of Cluster topology — and
//    its unscreened connection must not carry a policy command.
// 2. Rejection is terminal *under concurrency*. A connection, command, or
//    recovery probe that completes successfully after another task proved
//    Cluster topology must not be published, must not be returned as a success,
//    and must not make a failover health observer advertise a recovery.

/// RESP wire form of the command-name bulk string the fake server matches on.
const INFO_CMD: &[u8] = b"$4\r\nINFO\r\n";
const GET_CMD: &[u8] = b"$3\r\nGET\r\n";

/// How the fake server answers `INFO CLUSTER`.
#[derive(Clone, Copy)]
enum InfoBehavior {
    /// Answer with this text as a bulk string.
    Payload(&'static str),
    /// Answer with these raw RESP bytes (an error line, for example).
    Raw(&'static str),
    /// Accept and authenticate the connection, then never answer `INFO`.
    Never,
    /// Answer the FIRST screen with this text, then report Cluster topology on
    /// every later screen. Models an endpoint that is re-pointed at a Cluster
    /// node after Ferrum already screened and cached a connection to it, so the
    /// re-screen on the post-disconnect reconnect is what must catch it.
    PayloadThenCluster(&'static str),
    /// Answer the first `n` screens with this text, then report Cluster
    /// topology. Models an endpoint that a whole warm pool screened cleanly
    /// before the *background recovery probe* is the task that proves Cluster.
    PayloadForFirstScreens(&'static str, usize),
}

const CLUSTER_INFO: &str = "# Cluster\r\ncluster_enabled:1\r\n";

struct ScreenedServer {
    port: u16,
    shutdown: oneshot::Sender<()>,
    accepts: Arc<AtomicUsize>,
    infos: Arc<AtomicUsize>,
    gets: Arc<AtomicUsize>,
}

fn chunk_contains(chunk: &[u8], needle: &[u8]) -> bool {
    chunk.windows(needle.len()).any(|window| window == needle)
}

/// Number of RESP command arrays in one read chunk — the redis crate pipelines
/// its connection setup, so a single read can carry several commands.
fn command_count(chunk: &[u8]) -> usize {
    chunk.iter().filter(|&&byte| byte == b'*').count().max(1)
}

/// Minimal RESP server: `+OK` to every command except `INFO` (per
/// [`InfoBehavior`]), the standalone `TIME` screening probe (this host's
/// clock), and `GET` (always a nil bulk string). `info_delay` / `get_delay`
/// hold the corresponding reply *after* counting it, so a test can land a
/// concurrent topology rejection while that exact operation is in flight.
async fn spawn_screened_redis_server(
    info: InfoBehavior,
    info_delay: Duration,
    get_delay: Duration,
) -> ScreenedServer {
    spawn_screened_redis_server_with_drop(info, info_delay, get_delay, None).await
}

/// As [`spawn_screened_redis_server`], plus `drop_after_gets`: once a connection
/// has answered that many `GET`s, the server closes the socket instead of
/// replying. That is the physical disconnect a transparently reconnecting
/// redis-rs `ConnectionManager` would paper over without re-screening.
async fn spawn_screened_redis_server_with_drop(
    info: InfoBehavior,
    info_delay: Duration,
    get_delay: Duration,
    drop_after_gets: Option<usize>,
) -> ScreenedServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let infos = Arc::new(AtomicUsize::new(0));
    let gets = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let infos_task = Arc::clone(&infos);
    let gets_task = Arc::clone(&gets);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let infos = Arc::clone(&infos_task);
                    let gets = Arc::clone(&gets_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        // Per-connection GET count, so the drop applies to each
                        // physical socket independently.
                        let mut conn_gets = 0usize;
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            let chunk = &buf[..n];
                            let mut reply: Vec<u8> = Vec::new();
                            if chunk_contains(chunk, INFO_CMD) {
                                let screen_index = infos.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(info_delay).await;
                                match info {
                                    InfoBehavior::Payload(text) => {
                                        let len = text.len();
                                        let bulk = format!("${len}\r\n{text}\r\n");
                                        reply.extend_from_slice(bulk.as_bytes());
                                    }
                                    InfoBehavior::PayloadThenCluster(first) => {
                                        let text = if screen_index == 0 {
                                            first
                                        } else {
                                            CLUSTER_INFO
                                        };
                                        let len = text.len();
                                        let bulk = format!("${len}\r\n{text}\r\n");
                                        reply.extend_from_slice(bulk.as_bytes());
                                    }
                                    InfoBehavior::PayloadForFirstScreens(first, clean_screens) => {
                                        let text = if screen_index < clean_screens {
                                            first
                                        } else {
                                            CLUSTER_INFO
                                        };
                                        let len = text.len();
                                        let bulk = format!("${len}\r\n{text}\r\n");
                                        reply.extend_from_slice(bulk.as_bytes());
                                    }
                                    InfoBehavior::Raw(raw) => {
                                        reply.extend_from_slice(raw.as_bytes());
                                    }
                                    // Accepted, authenticated, silent.
                                    InfoBehavior::Never => continue,
                                }
                            } else if chunk_contains(chunk, TIME_CMD) {
                                // The standalone screening probe that follows a
                                // usable `INFO`. A `+OK` is not a clock, so the
                                // connection would be dropped unpublished and
                                // every case below would observe a refused
                                // endpoint instead of the behaviour under test.
                                reply.extend_from_slice(&host_clock_time_reply());
                            } else if chunk_contains(chunk, GET_CMD) {
                                gets.fetch_add(1, Ordering::Relaxed);
                                conn_gets += 1;
                                if drop_after_gets.is_some_and(|limit| conn_gets > limit) {
                                    // Physical disconnect: no reply, socket closed.
                                    break;
                                }
                                tokio::time::sleep(get_delay).await;
                                reply.extend_from_slice(b"$-1\r\n");
                            } else {
                                for _ in 0..command_count(chunk) {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    ScreenedServer {
        port,
        shutdown: shutdown_tx,
        accepts,
        infos,
        gets,
    }
}

fn screened_client(port: u16, connect_timeout_seconds: u64) -> RedisRateLimitClient {
    let url = format!("redis://127.0.0.1:{port}/0");
    let mut config = make_config(&url, false);
    config.connect_timeout_seconds = connect_timeout_seconds;
    // Long enough that no background recovery dial happens during a test.
    config.health_check_interval_seconds = 3600;
    config.pool_size = 1;
    redis_rate_limit_client_for_test(config)
}

/// Await a server-side counter reaching `target`, so a race is landed at a known
/// point rather than on a hopeful sleep.
async fn wait_for_count(counter: &Arc<AtomicUsize>, target: usize, what: &str) {
    for _ in 0..6_000 {
        if counter.load(Ordering::Relaxed) >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("{what} never reached {target}");
}

/// A RESP-compatible server that simply does not report `cluster_enabled` is not
/// proven to be anything, so it must keep serving policy operations.
#[tokio::test]
async fn a_server_without_a_cluster_enabled_field_still_serves_policy_operations() {
    let info = InfoBehavior::Payload("# Server\r\nredis_version:7.2.4\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let client = screened_client(server.port, 5);

    let served = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert_eq!(
        served,
        Ok(None),
        "an unknown topology must fall through to the reactive screen"
    );
    assert!(!client.is_topology_unsupported());
    assert!(client.is_available());
    assert_eq!(server.gets.load(Ordering::Relaxed), 1);

    let _ = server.shutdown.send(());
}

/// A server that answers `INFO` with an ordinary command error (unknown command,
/// restricted ACL) keeps the documented compatibility behavior.
#[tokio::test]
async fn an_unsupported_info_command_error_keeps_the_endpoint_usable() {
    let info = InfoBehavior::Raw("-ERR unknown command 'INFO'\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let client = screened_client(server.port, 5);

    let served = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert_eq!(
        served,
        Ok(None),
        "a server error reply to INFO is not proof of Cluster topology"
    );
    assert!(!client.is_topology_unsupported());
    assert!(client.is_available());

    let _ = server.shutdown.send(());
}

/// An `INFO` answered with a Cluster-only wire code is itself proof, even when
/// the server never reports `cluster_enabled`.
#[tokio::test]
async fn a_cluster_wire_error_on_the_info_probe_is_terminal() {
    let info = InfoBehavior::Raw("-MOVED 1234 127.0.0.1:7001\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let client = screened_client(server.port, 5);

    let refused = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert!(
        refused.is_err(),
        "a Cluster endpoint must not serve a policy operation"
    );
    assert!(
        client.is_topology_unsupported(),
        "a Cluster wire code on the screen proves the topology"
    );
    assert!(!client.is_available());
    assert_eq!(
        server.gets.load(Ordering::Relaxed),
        0,
        "no policy command may reach a refused endpoint"
    );

    let _ = server.shutdown.send(());
}

/// The finding that motivated the deadline: a server that accepts and
/// authenticates but never answers `INFO` must not hang the first enforcement
/// operation. The probe is bounded by `redis_connect_timeout_seconds`, and an
/// unanswered screen is an outage — not proof of Cluster topology.
#[tokio::test]
async fn an_endpoint_that_never_answers_info_fails_closed_within_the_connect_timeout() {
    let info = InfoBehavior::Never;
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    // One-second connect timeout, which now also bounds the topology probe.
    let client = screened_client(server.port, 1);

    let started = std::time::Instant::now();
    let refused = client.get_bytes("{ferrum%3Atest:probe}").await;
    let elapsed = started.elapsed();
    assert!(
        refused.is_err(),
        "an unscreened endpoint must fail closed instead of serving the command"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "the topology probe must be bounded by redis_connect_timeout_seconds, took {elapsed:?}"
    );
    assert!(!client.is_available());
    assert!(
        !client.is_topology_unsupported(),
        "an unanswered probe is a retryable outage, not proof of Cluster topology"
    );
    assert_eq!(server.infos.load(Ordering::Relaxed), 1);
    assert_eq!(
        server.gets.load(Ordering::Relaxed),
        0,
        "a policy command must never run on a connection that was not screened"
    );

    let _ = server.shutdown.send(());
}

/// Issue #5006: the proactive `INFO CLUSTER` screen on a NEW pooled connection
/// must obey the configured `redis_connect_timeout_seconds`, not redis-rs'
/// 500ms command-response default. A healthy server that answers `INFO` after
/// 750ms fits a 2-second screen; before the fix the inner cap refused it, and
/// every replacement pooled connection repeated the refusal even after the
/// background recovery probe (which never had the shorter cap) reported the
/// endpoint healthy.
#[tokio::test]
async fn a_slow_info_screen_still_fits_the_configured_probe_deadline() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let slow_screen = Duration::from_millis(750);
    let server = spawn_screened_redis_server(info, slow_screen, Duration::ZERO).await;
    let client = screened_client(server.port, 2);

    let served = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert_eq!(
        served,
        Ok(None),
        "an INFO answered inside the configured deadline must not refuse the endpoint"
    );
    assert!(client.is_available());
    assert!(!client.is_topology_unsupported());
    assert_eq!(server.infos.load(Ordering::Relaxed), 1);
    assert_eq!(
        server.gets.load(Ordering::Relaxed),
        1,
        "the screened connection must go on to serve the policy command"
    );

    let _ = server.shutdown.send(());
}

/// The relaxed screen bound is a deadline, not its removal: an `INFO` slower
/// than the configured deadline is still an ordinary retryable outage and the
/// unscreened connection still carries no command.
#[tokio::test]
async fn an_info_screen_slower_than_the_configured_deadline_fails_closed() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let over_deadline = Duration::from_millis(2_500);
    let server = spawn_screened_redis_server(info, over_deadline, Duration::ZERO).await;
    let client = screened_client(server.port, 1);

    let refused = client.get_bytes("{ferrum%3Atest:probe}").await;
    assert!(
        refused.is_err(),
        "a screen that misses its deadline must fail closed"
    );
    assert!(!client.is_available());
    assert!(
        !client.is_topology_unsupported(),
        "an unanswered probe is a retryable outage, not proof of Cluster topology"
    );
    assert_eq!(
        server.gets.load(Ordering::Relaxed),
        0,
        "a policy command must never run on a connection that was not screened"
    );

    let _ = server.shutdown.send(());
}

/// The relaxed bound is scoped to the screen. Once the connection is published,
/// ordinary commands keep a bounded per-command response deadline, so a backend
/// that goes silent mid-command cannot pin a hot-path request to the far larger
/// connect/screen budget.
#[tokio::test]
async fn a_screened_connection_still_bounds_ordinary_command_replies() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let stalled = Duration::from_secs(30);
    let server = spawn_screened_redis_server(info, Duration::ZERO, stalled).await;
    // A 60-second connect/screen budget: only the per-command response
    // deadline can end this GET.
    let client = screened_client(server.port, 60);

    let started = std::time::Instant::now();
    let refused = client.get_bytes("{ferrum%3Atest:stalled}").await;
    let elapsed = started.elapsed();
    assert!(
        refused.is_err(),
        "a silent command reply must not be awaited without a bound"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "ordinary commands must stay bounded after the screen, took {elapsed:?}"
    );
    assert!(!client.is_available());

    let _ = server.shutdown.send(());
}

/// A command whose reply lands *after* another task proved Cluster topology must
/// be reported as a failure, so the consumer's `redis_failure_policy` governs.
/// Over-counting one operation is safer than admitting traffic against a
/// topology this client cannot enforce on.
#[tokio::test]
async fn a_command_completing_after_a_topology_rejection_fails_closed() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let held = Duration::from_millis(300);
    let server = spawn_screened_redis_server(info, Duration::ZERO, held).await;
    let client = Arc::new(screened_client(server.port, 5));

    // Control: this fake really does answer the command successfully, so the
    // failure asserted below is attributable to the rejection alone.
    let control = client.get_bytes("{ferrum%3Atest:control}").await;
    assert_eq!(control, Ok(None));
    assert!(client.is_available());

    let racer = Arc::clone(&client);
    let raced_key = "{ferrum%3Atest:raced}";
    let inflight = tokio::spawn(async move { racer.get_bytes(raced_key).await });
    // The server now holds the racing GET's reply.
    wait_for_count(&server.gets, 2, "racing GET").await;
    client.mark_topology_unsupported_for_test();

    let raced = inflight.await.expect("racing task");
    assert!(
        raced.is_err(),
        "a command that completed after the rejection must not be a success"
    );
    assert!(
        !client.is_available(),
        "topology rejection must stay terminal for this client generation"
    );
    assert!(
        !client.observer_sees_available_for_test(),
        "a failover health observer must never see a refused endpoint as available"
    );

    // Later operations, and the redials they would trigger, stay disabled.
    let dials = server.accepts.load(Ordering::Relaxed);
    let after = client.get_bytes("{ferrum%3Atest:after}").await;
    assert!(after.is_err());
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        dials,
        "a rejected topology must never be redialed"
    );

    let _ = server.shutdown.send(());
}

/// A connection still being screened when another task proves Cluster topology
/// must never be published to the hot path, even though its own screen passed.
#[tokio::test]
async fn a_connection_screened_across_a_topology_rejection_is_never_published() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let held = Duration::from_millis(300);
    let server = spawn_screened_redis_server(info, held, Duration::ZERO).await;
    let client = Arc::new(screened_client(server.port, 5));

    let connecting = Arc::clone(&client);
    let inflight = tokio::spawn(async move { connecting.connect_cached_for_test().await });
    // The server now holds the screen's INFO reply.
    wait_for_count(&server.infos, 1, "screening INFO").await;
    client.mark_topology_unsupported_for_test();

    let published = inflight.await.expect("connecting task");
    assert!(
        !published,
        "a connection screened across a rejection must not be published"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        0,
        "no pool slot may hold a connection to a refused endpoint"
    );
    assert!(!client.is_available());
    assert!(!client.observer_sees_available_for_test());

    let _ = server.shutdown.send(());
}

/// The recovery checker's own race: its `PING` and topology screen both succeed,
/// but a rejection landed while the probe was in flight. It must not restore
/// availability, so no observer can advertise a false recovery.
#[tokio::test]
async fn a_recovery_probe_completing_after_a_rejection_advertises_no_recovery() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let held = Duration::from_millis(300);
    let server = spawn_screened_redis_server(info, held, Duration::ZERO).await;
    let url = format!("redis://127.0.0.1:{}/0", server.port);
    let mut config = make_config(&url, false);
    config.connect_timeout_seconds = 5;
    // Probe once per second so the race window is reached promptly.
    config.health_check_interval_seconds = 1;
    config.pool_size = 1;
    let client = redis_rate_limit_client_for_test(config);

    // Enter the state an outage produces: unavailable, recovery checker running.
    client.mark_unavailable_for_test();
    assert!(client.health_checker_started_for_test());

    // Let the recovery probe reach its topology screen, then prove Cluster
    // topology from another task while that probe is still in flight.
    wait_for_count(&server.infos, 1, "recovery screen INFO").await;
    client.mark_topology_unsupported_for_test();

    // The probe's PING and INFO both succeed after the rejection landed.
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !client.is_available(),
        "a successful recovery probe must not resurrect a refused endpoint"
    );
    assert!(
        !client.observer_sees_available_for_test(),
        "no false recovery may be advertised to a failover health observer"
    );
    assert!(client.is_topology_unsupported());

    let _ = server.shutdown.send(());
}

/// The background recovery probe can be the task that *proves* Cluster
/// topology. When it is, the slots a previously healthy pool cached must be
/// released there and then — not retained until the whole client generation
/// drops. The probe owns only a `Weak` handle to the pool, which is exactly
/// enough to clear it.
#[tokio::test]
async fn a_recovery_probe_proving_cluster_topology_clears_every_cached_pool_slot() {
    const POOL_SIZE: usize = 3;
    // Every warm-pool screen passes; the next screen (the recovery probe's)
    // reports Cluster.
    let clean = "# Cluster\r\ncluster_enabled:0\r\n";
    let info = InfoBehavior::PayloadForFirstScreens(clean, POOL_SIZE);
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let url = format!("redis://127.0.0.1:{}/0", server.port);
    let mut config = make_config(&url, false);
    config.connect_timeout_seconds = 5;
    // Probe once per second so the rejection lands promptly.
    config.health_check_interval_seconds = 1;
    config.pool_size = POOL_SIZE;
    let client = redis_rate_limit_client_for_test(config);

    // Arm the recovery checker FIRST: marking unavailable also clears the pool,
    // so warming afterwards is what leaves populated slots for the probe to
    // find. The recovery loop sleeps one interval before its first probe.
    client.mark_unavailable_for_test();
    assert!(client.health_checker_started_for_test());
    assert_eq!(client.warm_pool_for_test().await, POOL_SIZE);
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        POOL_SIZE,
        "the probe must start from a fully populated cache"
    );
    assert_eq!(server.infos.load(Ordering::Relaxed), POOL_SIZE);
    let warm_dials = server.accepts.load(Ordering::Relaxed);
    assert_eq!(warm_dials, POOL_SIZE);

    for _ in 0..6_000 {
        if client.is_topology_unsupported() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        client.is_topology_unsupported(),
        "the recovery probe's own screen must prove Cluster topology"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        0,
        "a rejection proven by the recovery probe must release every cached slot"
    );
    assert!(!client.is_available());
    assert!(!client.observer_sees_available_for_test());

    // Terminal: nothing re-establishes a slot, and the endpoint is never
    // redialed for policy work.
    assert_eq!(client.warm_pool_for_test().await, 0);
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);
    let probe_dials = server.accepts.load(Ordering::Relaxed);
    assert_eq!(
        probe_dials,
        warm_dials + 1,
        "only the recovery probe's own connection may follow the warm pool"
    );

    // Two further probe intervals: the loop must stay parked on the terminal
    // state rather than pinging, reconnecting, or repopulating the cache.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);
    assert!(client.is_topology_unsupported());
    assert!(!client.is_available());
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        probe_dials,
        "a rejected topology must never be redialed"
    );

    let _ = server.shutdown.send(());
}

// ── Failover admission must not latch a second recovery interval (GHSA-87rq) ─
//
// The failover limiter used to gate admission on BOTH the client's semantic
// availability and its own health-observer mirror. An ordinary command failure
// makes the client unavailable; the client republishes availability at most one
// health interval later, and the independent observer then needed a further
// interval before its mirror agreed. Under the fail-closed default that turned
// routine socket recycling into roughly two intervals of blanket refusals.
// `is_available()` is now the only admission gate.

/// A plain (non-Cluster) server error on `EXEC` — the ordinary retryable
/// failure a recycled socket produces, not a topology proof.
const TRANSACTION_FAILURE: &[u8] = b"-ERR simulated transient backend failure\r\n";
const MULTI_ARG: &[u8] = b"MULTI";
const EXEC_ARG: &[u8] = b"EXEC";
const INCR_ARG: &[u8] = b"INCR";
const INFO_ARG: &[u8] = b"INFO";
const TIME_ARG: &[u8] = b"TIME";

/// `GET`s one window contributes to a charge: one per older sub-bucket, plus
/// one on the read-only sub-bucket AFTER the charged one. Only the charged
/// bucket is written, so that is the whole ladder minus one.
const CHARGE_GETS_PER_WINDOW: usize =
    ferrum_edge::plugins::utils::redis_rate_limiter::REDIS_WINDOW_SUB_BUCKET_KEYS - 1;

/// Commands one window contributes to a charge transaction: every `GET`, plus
/// `INCR` and `EXPIRE` on the sub-bucket being charged. Only the `EXPIRE` is
/// `.ignore()`d, so the client pairs `CHARGE_COMMANDS_PER_WINDOW - 1` values.
const CHARGE_COMMANDS_PER_WINDOW: usize = CHARGE_GETS_PER_WINDOW + 5;

/// How the fake server answers the limiter's two transactions.
///
/// A charge is `MULTI` / (sub-bucket `GET` × K / `INCR` / `EXPIRE` plus legacy
/// `GET` / `INCR` / `EXPIRE`) per window / one
/// trailing `TIME` for the whole transaction / `EXEC`; the compensating
/// transaction a refusal issues is `MULTI` / `DECR` / `EXPIRE` / `EXEC` per
/// window and carries no clock. The server tells them apart by the queued
/// commands, so a script never has to hardcode a reply length.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TransactionScript {
    /// The FIRST charge fails with a plain server error; every later charge
    /// admits a fresh window.
    FirstChargeFails,
    /// Every charge reports an exhausted window, so the caller must refuse, and
    /// every compensating transaction succeeds.
    ChargeRefusesAndCompensates,
    /// The charge reports an exhausted window and the compensating transaction
    /// that follows fails with a plain server error.
    CompensationFails,
    /// The charge's `EXEC` array carries one element more than the client can
    /// pair with a window. A RESP-compatible server that frames a transaction
    /// differently — or a future change to how an ignored command is filtered
    /// out of an atomic pipeline's reply — lands here.
    ChargeReplyIsUnpairable,
}

/// `EXEC` array for a charge: per window one `GET` per older sub-bucket (nil or
/// an exhausted count), then `INCR` (the post-increment count) and `EXPIRE`,
/// followed by the legacy previous `GET`, current `INCR`, and `EXPIRE`,
/// and finally the one trailing `TIME` the charge queues once per transaction.
///
/// The trailing clock is there because this fixture answers the standalone
/// probe with a clock, so the client is in server-clock mode and queues `TIME`
/// last. Only the `EXPIRE`s are `.ignore()`d, so the client pairs
/// `windows * REDIS_WINDOW_SUB_BUCKET_KEYS` counters plus that clock.
fn charge_reply(windows: usize, exhausted: bool) -> Vec<u8> {
    let values = windows * CHARGE_COMMANDS_PER_WINDOW + 1;
    let mut reply = format!("*{values}\r\n").into_bytes();
    let older: &[u8] = if exhausted { b":9\r\n" } else { b"$-1\r\n" };
    // The charged sub-bucket's post-increment `INCR`, then its ignored `EXPIRE`.
    let charged: &[u8] = if exhausted {
        b":9\r\n:1\r\n"
    } else {
        b":1\r\n:1\r\n"
    };
    for _ in 0..windows {
        for _ in 0..CHARGE_GETS_PER_WINDOW {
            reply.extend_from_slice(older);
        }
        reply.extend_from_slice(charged);
        reply.extend_from_slice(older);
        reply.extend_from_slice(charged);
    }
    reply.extend_from_slice(&host_clock_time_reply());
    reply
}

/// Wait until every detached compensation this client issued has completed.
///
/// A refusal hands its charge back from a task holding the client `Arc`, not
/// from the request future, so the refusal returns before the `DECR` reaches
/// the server. Coverage that reads the server's counters — or the client's
/// availability — straight afterwards must wait for the hand-back instead of
/// racing it.
async fn await_compensations(client: &Arc<RedisRateLimitClient>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while client.pending_compensations_for_test() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "detached compensations did not drain"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// `EXEC` array for a compensation: sub-bucket and legacy `DECR`/`EXPIRE`. All are
/// ignored by the client, so only the shape matters.
fn compensation_reply(windows: usize) -> Vec<u8> {
    let mut reply = format!("*{}\r\n", windows * 4).into_bytes();
    for _ in 0..windows {
        reply.extend_from_slice(b":0\r\n:1\r\n:0\r\n:1\r\n");
    }
    reply
}

struct TransactionServer {
    port: u16,
    shutdown: oneshot::Sender<()>,
    accepts: Arc<AtomicUsize>,
    transactions: Arc<AtomicUsize>,
    compensations: Arc<AtomicUsize>,
}

/// Offset of the `\r\n` that terminates the RESP line starting at `from`.
fn resp_line_end(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| from + index)
}

/// Pull one COMPLETE RESP command array out of `pending`, or `None` while the
/// buffer holds only part of one.
///
/// Framing matters here: a charge and its compensation are answered
/// differently, so a chunk-substring stub that split or merged them would
/// desynchronize the connection.
fn take_resp_command(pending: &mut Vec<u8>) -> Option<Vec<Vec<u8>>> {
    let end = resp_line_end(pending, 0)?;
    if pending.first() != Some(&b'*') {
        return None;
    }
    let count: usize = std::str::from_utf8(&pending[1..end]).ok()?.parse().ok()?;
    let mut position = end + 2;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let end = resp_line_end(pending, position)?;
        if pending.get(position) != Some(&b'$') {
            return None;
        }
        let length: usize = std::str::from_utf8(&pending[position + 1..end])
            .ok()?
            .parse()
            .ok()?;
        let start = end + 2;
        if pending.len() < start + length + 2 {
            return None;
        }
        args.push(pending[start..start + length].to_vec());
        position = start + length + 2;
    }
    pending.drain(..position);
    Some(args)
}

/// Screens clean on every connection — including the standalone `TIME` probe,
/// which gets this host's clock so the client runs in the server-clock mode a
/// real Redis puts it in — and answers each `MULTI`/`EXEC` the limiter sends
/// according to `script`.
async fn spawn_transaction_redis_server(script: TransactionScript) -> TransactionServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let transactions = Arc::new(AtomicUsize::new(0));
    let compensations = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let transactions_task = Arc::clone(&transactions);
    let compensations_task = Arc::clone(&compensations);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let transactions = Arc::clone(&transactions_task);
                    let compensations = Arc::clone(&compensations_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        let mut pending: Vec<u8> = Vec::new();
                        let mut queued: Vec<Vec<u8>> = Vec::new();
                        let mut in_transaction = false;
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            pending.extend_from_slice(&buf[..n]);
                            let mut reply: Vec<u8> = Vec::new();
                            while let Some(args) = take_resp_command(&mut pending) {
                                let name = args.first().cloned().unwrap_or_default();
                                if name.eq_ignore_ascii_case(MULTI_ARG) {
                                    in_transaction = true;
                                    queued.clear();
                                    reply.extend_from_slice(b"+OK\r\n");
                                } else if name.eq_ignore_ascii_case(EXEC_ARG) {
                                    in_transaction = false;
                                    let charge = queued
                                        .iter()
                                        .any(|command| command.eq_ignore_ascii_case(INCR_ARG));
                                    let clocked = queued
                                        .iter()
                                        .any(|command| command.eq_ignore_ascii_case(TIME_ARG));
                                    // A charge queues one trailing `TIME` for the
                                    // whole transaction, not one per window, so
                                    // it is excluded before the per-window
                                    // commands are counted.
                                    let ladder = queued.len() - usize::from(clocked);
                                    let windows = if charge {
                                        ladder / CHARGE_COMMANDS_PER_WINDOW
                                    } else {
                                        queued.len() / 4
                                    };
                                    let index = if charge {
                                        transactions.fetch_add(1, Ordering::Relaxed)
                                    } else {
                                        compensations.fetch_add(1, Ordering::Relaxed)
                                    };
                                    match (script, charge) {
                                        (TransactionScript::FirstChargeFails, true) => {
                                            if index == 0 {
                                                reply.extend_from_slice(TRANSACTION_FAILURE);
                                            } else {
                                                reply.extend(charge_reply(windows, false));
                                            }
                                        }
                                        (TransactionScript::FirstChargeFails, false) => {
                                            reply.extend(compensation_reply(windows));
                                        }
                                        (TransactionScript::ChargeReplyIsUnpairable, true) => {
                                            // One extra integer beyond the
                                            // charge's own commands: the client
                                            // filters the ignored `EXPIRE`
                                            // slots by index, so the surviving
                                            // count no longer divides into
                                            // whole sub-bucket ladders even
                                            // after the trailing server clock
                                            // is accounted for.
                                            let values = windows * CHARGE_COMMANDS_PER_WINDOW + 1;
                                            let mut unpairable =
                                                format!("*{}\r\n", values + 1).into_bytes();
                                            for _ in 0..values {
                                                unpairable.extend_from_slice(b":1\r\n");
                                            }
                                            unpairable.extend_from_slice(&host_clock_time_reply());
                                            reply.extend(unpairable);
                                        }
                                        (_, true) => reply.extend(charge_reply(windows, true)),
                                        (TransactionScript::CompensationFails, false) => {
                                            reply.extend_from_slice(TRANSACTION_FAILURE);
                                        }
                                        (_, false) => reply.extend(compensation_reply(windows)),
                                    }
                                } else if name.eq_ignore_ascii_case(INFO_ARG) {
                                    // The topology screen runs at connect, never
                                    // inside a transaction.
                                    let text = "# Cluster\r\ncluster_enabled:0\r\n";
                                    let len = text.len();
                                    let bulk = format!("${len}\r\n{text}\r\n");
                                    reply.extend_from_slice(bulk.as_bytes());
                                } else if in_transaction {
                                    // Including the `TIME` a charge queues last:
                                    // inside `MULTI` it is `+QUEUED` like every
                                    // other command and answered by the `EXEC`
                                    // array that `charge_reply` builds.
                                    queued.push(name);
                                    reply.extend_from_slice(b"+QUEUED\r\n");
                                } else if name.eq_ignore_ascii_case(TIME_ARG) {
                                    // The standalone screening probe. Answering
                                    // a clock is what a real Redis does, and it
                                    // is what puts the client in the
                                    // server-clock mode `charge_reply` is
                                    // shaped for.
                                    reply.extend_from_slice(&host_clock_time_reply());
                                } else {
                                    reply.extend_from_slice(b"+OK\r\n");
                                }
                            }
                            if reply.is_empty() {
                                continue;
                            }
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    TransactionServer {
        port,
        shutdown: shutdown_tx,
        accepts,
        transactions,
        compensations,
    }
}

/// `rate_limiting` config pointed at the fake server on `port`, pinned to one
/// pooled connection and to explicit fail-closed so an outage is observable.
///
/// The health interval is long enough that neither the client's recovery
/// checker nor the failover observer can tick during these tests: every
/// transition is one the test performs explicitly.
fn transaction_backend_config(port: u16) -> serde_json::Value {
    json!({
        "sync_mode": "redis",
        "redis_url": format!("redis://127.0.0.1:{port}/0"),
        "redis_pool_size": 1,
        "redis_failure_policy": "fail_closed",
        "redis_health_check_interval_seconds": 3600,
    })
}

/// Once the client's availability signal recovers, the very next admission is
/// eligible for centralized enforcement — no observer tick in between. A
/// terminal topology rejection still can never be overruled.
#[tokio::test]
async fn failover_admission_resumes_on_client_recovery_without_an_observer_tick() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitWindowSpec,
        RedisFailurePolicy,
    };

    let server = spawn_transaction_redis_server(TransactionScript::FirstChargeFails).await;
    let accepts = Arc::clone(&server.accepts);
    let transactions = Arc::clone(&server.transactions);

    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &transaction_backend_config(server.port),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    assert_eq!(
        backend.redis_failure_policy(),
        Some(RedisFailurePolicy::FailClosed),
        "this coverage is about explicit fail-closed recovery latency"
    );
    let client = backend
        .redis_client_arc_for_test()
        .expect("failover backend must own a Redis client");
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1_000,
        duration: Duration::from_secs(60),
    }]);

    // 1. The first centralized transaction fails, so the client marks itself
    //    unavailable and the fail-closed policy refuses. This is the transition
    //    that used to drive the failover mirror false as well.
    let first = backend
        .check_with_redis_key_and_local_capacity(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("fail-closed refusal is an outcome, not a capacity denial");
    assert!(!first.allowed);
    assert!(first.enforcement_unavailable);
    assert!(!client.is_available());
    assert!(!client.is_topology_unsupported());
    assert_eq!(transactions.load(Ordering::Relaxed), 1);
    let dials_after_outage = accepts.load(Ordering::Relaxed);
    assert_eq!(dials_after_outage, 1);

    // 2. The client itself recovers — what a successful recovery probe does.
    //    No observer tick can have happened: its interval is an hour away.
    assert!(client.publish_reachable_for_test());
    assert!(client.is_available());

    // 3. The very next admission must be centrally enforced. Before the fix the
    //    limiter also required its own observer mirror to agree, so this
    //    admission was refused for up to another whole health interval.
    let second = backend
        .check_with_redis_key_and_local_capacity(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("outcome");
    assert!(
        second.allowed && !second.enforcement_unavailable,
        "admission must be centrally enforced as soon as the client is available \
         again, without waiting for the failover observer's own interval"
    );
    assert_eq!(
        transactions.load(Ordering::Relaxed),
        2,
        "the recovered admission must actually reach Redis"
    );
    assert!(accepts.load(Ordering::Relaxed) > dials_after_outage);

    // 4. A terminal topology rejection can never be overruled: no publication
    //    restores availability, and admission never redials the endpoint.
    client.mark_topology_unsupported_for_test();
    assert!(!client.publish_reachable_for_test());
    assert!(!client.is_available());
    let dials_after_rejection = accepts.load(Ordering::Relaxed);
    let refused = backend
        .check_with_redis_key_and_local_capacity(
            "identity-b".to_string(),
            || "{ferrum%3Atest:identity-b}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("outcome");
    assert!(!refused.allowed);
    assert!(refused.enforcement_unavailable);
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        dials_after_rejection,
        "a refused topology must not be redialed by admission"
    );
    assert_eq!(
        transactions.load(Ordering::Relaxed),
        2,
        "no policy command may run against a refused endpoint"
    );
    assert!(client.is_topology_unsupported());

    let _ = server.shutdown.send(());
}

/// Issue #5517: a quota refusal hands its charge straight back, on the SAME
/// pooled connection, and is an ordinary decision rather than an outage — so a
/// client above its rate keeps being evaluated instead of re-arming its own
/// exhaustion on every retry.
#[tokio::test]
async fn a_refused_window_hands_its_charge_back_on_the_pooled_connection() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitWindowSpec,
    };

    let server =
        spawn_transaction_redis_server(TransactionScript::ChargeRefusesAndCompensates).await;
    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &transaction_backend_config(server.port),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    let client = backend
        .redis_client_arc_for_test()
        .expect("backend must own a Redis client");
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1,
        duration: Duration::from_secs(60),
    }]);

    for attempt in 1..=2 {
        let outcome = backend
            .check_with_redis_key_and_local_capacity(
                "identity-a".to_string(),
                || "{ferrum%3Atest:identity-a}".to_string(),
                &op,
                1_000,
            )
            .await
            .expect("outcome");
        assert!(
            !outcome.allowed,
            "attempt {attempt}: the window is exhausted"
        );
        assert!(
            !outcome.enforcement_unavailable,
            "attempt {attempt}: a quota refusal is a decision, not an outage"
        );
        assert!(
            !outcome.local_fallback,
            "attempt {attempt}: a centralized refusal must not mint a per-process budget"
        );
        assert_eq!(
            server.transactions.load(Ordering::Relaxed),
            attempt,
            "attempt {attempt}: exactly one charge per decision"
        );
        await_compensations(&client).await;
        assert_eq!(
            server.compensations.load(Ordering::Relaxed),
            attempt,
            "attempt {attempt}: the refused charge must be handed straight back"
        );
    }
    assert!(
        client.is_available(),
        "a refusal must never mark the centralized store unavailable"
    );
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        1,
        "charge and compensation share the pooled connection; neither dials"
    );

    let _ = server.shutdown.send(());
}

/// A compensation that cannot be delivered is an ordinary Redis failure: the
/// refusal it belongs to still stands, and the configured `redis_failure_policy`
/// governs the NEXT decision rather than this one.
#[tokio::test]
async fn a_failed_compensation_is_reported_as_a_redis_failure() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitWindowSpec,
    };

    let server = spawn_transaction_redis_server(TransactionScript::CompensationFails).await;
    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &transaction_backend_config(server.port),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    let client = backend
        .redis_client_arc_for_test()
        .expect("backend must own a Redis client");
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1,
        duration: Duration::from_secs(60),
    }]);

    let refused = backend
        .check_with_redis_key_and_local_capacity(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("outcome");
    assert!(!refused.allowed, "the window is exhausted");
    assert!(
        !refused.enforcement_unavailable,
        "the charge decided this request; only the hand-back failed"
    );
    assert_eq!(server.transactions.load(Ordering::Relaxed), 1);
    await_compensations(&client).await;
    assert_eq!(server.compensations.load(Ordering::Relaxed), 1);
    assert!(
        !client.is_available(),
        "a failed compensation must be recorded as a Redis failure"
    );

    // The NEXT decision is the one the failure policy governs, and it must not
    // redial the endpoint the client has already marked unavailable.
    let next = backend
        .check_with_redis_key_and_local_capacity(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("outcome");
    assert!(!next.allowed && next.enforcement_unavailable);
    assert_eq!(
        server.transactions.load(Ordering::Relaxed),
        1,
        "an unavailable client must not charge another window"
    );
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);

    let _ = server.shutdown.send(());
}

/// A charge reply this code cannot pair with its windows is an UNUSABLE
/// endpoint, not a quota decision, and the `INCR`s have already landed.
///
/// The caller returns `Err` before it can reach its own refusal branch, so
/// nothing compensates that charge. Without marking the client unavailable the
/// counters would climb monotonically to the key TTL while every request
/// re-charged a reply this code still cannot pair, `is_available()` would never
/// flip, and there would be neither backoff nor an availability transition —
/// just a permanent loop. Marking it matches the `Err` arm's accounting and
/// hands the next decision to `redis_failure_policy`.
#[tokio::test]
async fn an_unpairable_charge_reply_marks_the_client_unavailable() {
    use ferrum_edge::plugins::utils::http_client::PluginHttpClient;
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitWindowSpec,
    };

    let server = spawn_transaction_redis_server(TransactionScript::ChargeReplyIsUnpairable).await;
    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &transaction_backend_config(server.port),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    let client = backend
        .redis_client_arc_for_test()
        .expect("backend must own a Redis client");
    let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
        limit: 1,
        duration: Duration::from_secs(60),
    }]);

    let first = backend
        .check_with_redis_key_and_local_capacity(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("outcome");
    assert!(
        !first.allowed && first.enforcement_unavailable,
        "an unusable reply shape is an outage, governed by redis_failure_policy"
    );
    assert!(
        !client.is_available(),
        "an unpairable reply must mark the client unavailable, exactly as a \
         command error does"
    );
    assert_eq!(
        server.transactions.load(Ordering::Relaxed),
        1,
        "the charge that could not be paired is the only one issued"
    );
    assert_eq!(
        server.compensations.load(Ordering::Relaxed),
        0,
        "the caller never reached its refusal branch, so nothing compensates"
    );

    // No backoff is the failure this closes: an unavailable client must not
    // charge the endpoint again on the next request.
    let next = backend
        .check_with_redis_key_and_local_capacity(
            "identity-a".to_string(),
            || "{ferrum%3Atest:identity-a}".to_string(),
            &op,
            1_000,
        )
        .await
        .expect("outcome");
    assert!(!next.allowed && next.enforcement_unavailable);
    assert_eq!(
        server.transactions.load(Ordering::Relaxed),
        1,
        "an unavailable client must not charge another window"
    );
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);

    let _ = server.shutdown.send(());
}

/// Issue #5517 design pins. The HTTP-window decision is charge-then-compensate
/// on the SHARED POOLED connection: no per-request dial, no `WATCH` retry loop,
/// no server-side scripting, and no refusal that keeps its charge.
#[test]
fn http_window_admission_is_pooled_plain_resp_and_hands_back_a_refused_charge() {
    let redis = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    let limiter = include_str!("../../../src/plugins/utils/rate_limit.rs");

    for (helper, command) in [
        ("pub async fn charge_rate_limit_windows(", "\"INCR\""),
        ("pub async fn uncharge_rate_limit_windows(", "\"DECR\""),
    ] {
        let start = redis
            .find(helper)
            .unwrap_or_else(|| panic!("{helper} must exist"));
        let rest = &redis[start..];
        let end = rest[1..]
            .find("\n    /// ")
            .map(|index| index + 1)
            .unwrap_or(rest.len());
        let body = &rest[..end];
        assert!(
            body.contains("self.get_connection().await"),
            "{helper} must run on the shared pooled multiplexed slots"
        );
        assert!(
            !body.contains("get_dedicated_connection"),
            "{helper} must never dial a per-request connection"
        );
        assert_eq!(
            body.matches("pipeline.atomic();").count(),
            1,
            "{helper} must be exactly one atomic MULTI/EXEC"
        );
        assert!(
            body.contains(command),
            "{helper} must issue {command} for every window"
        );
        for forbidden in ["WATCH", "EVAL", "SCRIPT"] {
            assert!(
                !body.contains(forbidden),
                "{helper} must stay plain RESP; found {forbidden}"
            );
        }
    }

    let start = limiter
        .find("async fn check_http_windows_redis(")
        .expect("Redis admission entry point");
    let rest = &limiter[start..];
    let end = rest
        .find("\n}\n")
        .map(|index| index + 2)
        .unwrap_or(rest.len());
    let body = &rest[..end];
    let charge = body
        .find("redis.charge_rate_limit_windows(charges.as_slice())")
        .expect("admission must charge every window in one transaction");
    let refusal = body
        .find("if let Some(spec) = refused {")
        .expect("admission must have a single refusal branch");
    // Exactly two hand-backs, and the review of the sub-bucket rework is why
    // there are two: the staleness rebuild abandons its own pass inside the
    // charge loop (before any decision is derived), and the refusal branch
    // hands back after one. An admitted request still reaches neither.
    let rollover_handback = body
        .find(".spawn_uncharge_rate_limit_windows(charges)")
        .expect("an abandoned stale pass must hand its charge back");
    let refusal_handback = body
        .rfind(".spawn_uncharge_rate_limit_windows(charges)")
        .expect("a refusal must hand the charge back");
    let pass_bound = body
        .find("if pass >= MAX_REDIS_CHARGE_PASSES {")
        .expect("the staleness rebuild must be bounded");
    assert!(
        charge < rollover_handback && rollover_handback < pass_bound,
        "the abandoned pass must hand its charge back before the bound refuses"
    );
    assert!(
        pass_bound < refusal && refusal < refusal_handback,
        "the charge must precede the decision, and the refusal's hand-back must \
         sit behind the refusal branch"
    );
    assert_eq!(
        body.matches("uncharge_rate_limit_windows").count(),
        2,
        "only the abandoned pass and the refusal compensate; an admitted request \
         must never compensate"
    );
    // The hand-back must NOT be tied to the request future. Plugin hooks run
    // under `tokio::time::timeout_at`, so a gRPC deadline or a client
    // disconnect drops the hook future; awaiting the compensation inline let
    // that cancellation strand the charge until the window's TTL elapsed, with
    // no failure accounting and no `redis_failure_policy` involvement.
    let spawner = redis
        .find("pub async fn spawn_uncharge_rate_limit_windows(")
        .expect("the detached compensation entry point must exist");
    let spawner_body = {
        let rest = &redis[spawner..];
        let end = rest[1..]
            .find("\n    /// ")
            .map(|index| index + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    };
    assert!(
        spawner_body.contains("self: Arc<Self>"),
        "the compensation task must own the client Arc, not borrow the caller's"
    );
    assert!(
        spawner_body.contains("handle.spawn(compensate)"),
        "the compensation must be detached from the request future"
    );
    assert!(
        spawner_body.contains("uncharge_rate_limit_windows(charges.as_slice())"),
        "the detached task must issue the compensating transaction"
    );

    for forbidden in [
        "EVALSHA",
        "SCRIPT LOAD",
        "@scripting",
        "HTTP_WINDOW_ADMISSION",
        "admit_rate_limit_windows",
    ] {
        assert!(
            !redis.contains(forbidden) && !limiter.contains(forbidden),
            "the rejected server-side script design must be gone; found {forbidden}"
        );
    }

    // Issue #5517 asked for this audit explicitly: the GraphQL and gRPC-method
    // quotas must reach the SAME helper, not a private copy that keeps the old
    // charge-a-refusal behaviour.
    for consumer in [
        include_str!("../../../src/plugins/rate_limiting.rs"),
        include_str!("../../../src/plugins/graphql.rs"),
        include_str!("../../../src/plugins/grpc_method_router.rs"),
    ] {
        assert!(
            consumer.contains("RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>"),
            "every HTTP-family quota must admit through the shared window helper"
        );
    }
}

// ── Cached pool must not transparently reconnect (GHSA-87rq root review) ──
//
// redis-rs `ConnectionManager` re-establishes its physical socket internally.
// Ferrum screens DNS, egress, and `INFO CLUSTER` only when it creates a
// connection itself, so a manager in the hot-path pool could replace a screened
// socket with an unscreened one after any blip. The pool therefore caches plain
// `MultiplexedConnection`s: a broken connection surfaces its I/O error, the pool
// is cleared, and the next operation re-establishes through the screened path.

/// Static + type pin: the hot-path pool caches a non-reconnecting
/// `MultiplexedConnection`, never a `ConnectionManager`, and no connection
/// helper constructs one.
#[test]
fn cached_pool_pins_multiplexed_connection_not_connection_manager() {
    let source = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");

    assert!(
        source.contains("connection: ArcSwap<Option<redis::aio::MultiplexedConnection>>"),
        "pool slots must cache MultiplexedConnection"
    );
    assert!(
        !source.contains("ArcSwap<Option<redis::aio::ConnectionManager>>"),
        "pool slots must not cache a transparently reconnecting ConnectionManager"
    );
    assert!(
        source.contains(
            "async fn get_or_connect_slot(&self, idx: usize) -> Option<redis::aio::MultiplexedConnection>"
        ),
        "pooled establishment must return MultiplexedConnection"
    );
    assert!(
        source.contains(
            "async fn get_connection(&self) -> Option<redis::aio::MultiplexedConnection>"
        ),
        "pooled accessor must return MultiplexedConnection"
    );

    // No code path may construct a manager or its config any more.
    for banned in [
        "redis::aio::ConnectionManager::new",
        "redis::aio::ConnectionManagerConfig",
        "fn connect_manager",
    ] {
        assert!(
            !source.contains(banned),
            "obsolete ConnectionManager construction still present: {banned}"
        );
    }

    let type_name = RedisRateLimitClient::cached_pool_connection_type_name_for_test();
    assert_eq!(
        type_name,
        std::any::type_name::<redis::aio::MultiplexedConnection>()
    );
    assert!(
        !type_name.contains("ConnectionManager"),
        "pooled connection type must not be ConnectionManager: {type_name}"
    );

    // Both connect helpers dial multiplexed connections directly, and the
    // pooled path screens topology (and arms the per-command response
    // deadline) before publishing into the ArcSwap slot.
    let publish = source
        .find("slot.connection.store(Arc::new(Some(conn.clone())))")
        .expect("pooled publication site");
    let establish = source
        .find("match self.connect_multiplexed(client).await {")
        .expect("pooled establishment site");
    let screen = source[establish..publish]
        .find("self.screen_and_arm(&mut conn)")
        .expect("pooled path must screen topology before publishing");
    assert!(
        screen > 0,
        "topology screen must sit between connect and publication"
    );
}

/// A pooled connection that is physically disconnected must not be silently
/// replaced by redis-rs. The failing command fails, the pool is cleared, and the
/// re-established connection is screened again (`INFO CLUSTER` per socket).
#[tokio::test]
async fn pooled_reconnect_after_disconnect_reruns_the_topology_screen() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let server =
        spawn_screened_redis_server_with_drop(info, Duration::ZERO, Duration::ZERO, Some(1)).await;
    let client = screened_client(server.port, 5);

    // First operation establishes and screens exactly one physical connection.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    assert_eq!(server.accepts.load(Ordering::Relaxed), 1);
    assert_eq!(server.infos.load(Ordering::Relaxed), 1);
    assert_eq!(client.cached_pool_cardinality_for_test(), 1);

    // Second operation hits the server's disconnect. It must FAIL (not silently
    // ride a redis-rs reconnect) and must drop the cached slot.
    assert_eq!(
        client.get_bytes("{ferrum%3Atest:probe}").await,
        Err(()),
        "a disconnected pooled connection must fail the operation, not auto-reconnect"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        0,
        "an I/O failure must clear the cached pool"
    );
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        1,
        "redis-rs must not have dialled a replacement connection on its own"
    );

    // Third operation re-establishes — through the full screened path.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        2,
        "recovery must open a new physical connection"
    );
    assert_eq!(
        server.infos.load(Ordering::Relaxed),
        2,
        "every newly established pooled connection must be topology-screened"
    );
    assert_eq!(
        client.cached_pool_cardinality_for_test(),
        1,
        "the pool stays bounded at redis_pool_size across reconnects"
    );

    let _ = server.shutdown.send(());
}

/// The topology-after-disconnect seam: an endpoint that screened clean, then
/// disconnected, then came back reporting Cluster topology must be caught by the
/// re-screen and refused terminally. A transparent reconnect would have skipped
/// that screen entirely and kept serving policy operations.
#[tokio::test]
async fn cluster_topology_appearing_after_a_disconnect_is_caught_by_the_rescreen() {
    let info = InfoBehavior::PayloadThenCluster("# Cluster\r\ncluster_enabled:0\r\n");
    let server =
        spawn_screened_redis_server_with_drop(info, Duration::ZERO, Duration::ZERO, Some(1)).await;
    let client = screened_client(server.port, 5);

    // Screened clean, serving normally.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    assert!(!client.is_topology_unsupported());

    // Disconnect fails the in-flight operation and clears the pool.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Err(()));
    assert!(
        !client.is_topology_unsupported(),
        "an ordinary disconnect is an outage, never proof of Cluster topology"
    );

    // The reconnect re-screens and now sees cluster_enabled:1 — terminal refusal.
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Err(()));
    assert!(
        client.is_topology_unsupported(),
        "the post-disconnect re-screen must catch a Cluster endpoint"
    );
    assert!(!client.is_available());
    assert_eq!(client.cached_pool_cardinality_for_test(), 0);

    // Terminal: no further dialling of the refused endpoint.
    let accepts_at_rejection = server.accepts.load(Ordering::Relaxed);
    assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Err(()));
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        accepts_at_rejection,
        "a refused topology must never be redialled"
    );

    let _ = server.shutdown.send(());
}

/// Every slot of a multi-slot pool is screened on establishment, and the pool
/// never exceeds `redis_pool_size` physical connections.
#[tokio::test]
async fn every_pool_slot_is_screened_and_the_pool_stays_bounded() {
    let info = InfoBehavior::Payload("# Cluster\r\ncluster_enabled:0\r\n");
    let server = spawn_screened_redis_server(info, Duration::ZERO, Duration::ZERO).await;
    let url = format!("redis://127.0.0.1:{}/0", server.port);
    let mut config = make_config(&url, false);
    config.pool_size = 3;
    config.health_check_interval_seconds = 3600;
    let client = redis_rate_limit_client_for_test(config);

    assert_eq!(client.warm_pool_for_test().await, 3);
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);
    assert_eq!(server.accepts.load(Ordering::Relaxed), 3);
    assert_eq!(
        server.infos.load(Ordering::Relaxed),
        3,
        "each pool slot must be screened on establishment"
    );

    // Many more operations than slots must reuse the bounded pool, not dial.
    for _ in 0..12 {
        assert_eq!(client.get_bytes("{ferrum%3Atest:probe}").await, Ok(None));
    }
    assert_eq!(
        server.accepts.load(Ordering::Relaxed),
        3,
        "the round-robin pool must stay bounded at redis_pool_size"
    );
    assert_eq!(server.infos.load(Ordering::Relaxed), 3);
    assert_eq!(client.cached_pool_cardinality_for_test(), 3);

    let _ = server.shutdown.send(());
}

// ── Identity-bearing keys must never reach operational logs (GHSA-87rq) ───
//
// Redis/rate-limit keys embed the enforcement identity dimension: internal
// consumer usernames, `ctx.authenticated_identity`, and SPIFFE IDs. Emitting
// them in a warning writes those identities into every configured log sink at
// attacker-influenced rates. Diagnostics keep only bounded, non-identifying
// context (operation name, redacted endpoint, pool slot, plugin name, static
// topology reason, Redis error). Hashes/encodings are NOT an acceptable
// substitute — they are still per-identity correlators.

/// The eight limiter surfaces that talk to the shared Redis client.
fn identity_log_guard_sources() -> [(&'static str, &'static str); 8] {
    [
        (
            "src/plugins/utils/redis_rate_limiter.rs",
            include_str!("../../../src/plugins/utils/redis_rate_limiter.rs"),
        ),
        (
            "src/plugins/utils/rate_limit.rs",
            include_str!("../../../src/plugins/utils/rate_limit.rs"),
        ),
        (
            "src/plugins/rate_limiting.rs",
            include_str!("../../../src/plugins/rate_limiting.rs"),
        ),
        (
            "src/plugins/ai_rate_limiter.rs",
            include_str!("../../../src/plugins/ai_rate_limiter.rs"),
        ),
        (
            "src/plugins/ws_rate_limiting.rs",
            include_str!("../../../src/plugins/ws_rate_limiting.rs"),
        ),
        (
            "src/plugins/udp_rate_limiting.rs",
            include_str!("../../../src/plugins/udp_rate_limiting.rs"),
        ),
        // The remaining two Redis-backed enforcement consumers. They do not log
        // a rate key today, and this canary is what keeps that true: both build
        // an identity-bearing key (`limit_by` consumer/identity/SPIFFE/IP) and
        // both gained a fail-closed refusal arm here, which is exactly the kind
        // of edit that tends to add a "which key?" diagnostic.
        (
            "src/plugins/graphql.rs",
            include_str!("../../../src/plugins/graphql.rs"),
        ),
        (
            "src/plugins/grpc_method_router.rs",
            include_str!("../../../src/plugins/grpc_method_router.rs"),
        ),
    ]
}

/// Rust source with comments blanked out and string/char literal spans marked.
///
/// The mask is what makes the field/paren structure below trustworthy: a `,`,
/// `(`, or `//` inside a literal is text, not syntax.
struct MaskedSource {
    chars: Vec<char>,
    in_literal: Vec<bool>,
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn mask_source(source: &str) -> MaskedSource {
    let chars: Vec<char> = source.chars().collect();
    let mut out = chars.clone();
    let mut in_literal = vec![false; chars.len()];
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];

        // Line comment.
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                out[i] = ' ';
                i += 1;
            }
            continue;
        }

        // Block comment (Rust allows nesting).
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 1usize;
            out[i] = ' ';
            out[i + 1] = ' ';
            i += 2;
            while i < chars.len() && depth > 0 {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                    continue;
                }
                if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    out[i] = ' ';
                    out[i + 1] = ' ';
                    i += 2;
                    continue;
                }
                if chars[i] != '\n' {
                    out[i] = ' ';
                }
                i += 1;
            }
            continue;
        }

        // Raw string: r"…", r#"…"#, br#"…"#.
        if (c == 'r' || c == 'b') && (i == 0 || !is_ident_char(chars[i - 1])) {
            let mut j = i + 1;
            let raw = c == 'r' || chars.get(j) == Some(&'r');
            if c == 'b' && chars.get(j) == Some(&'r') {
                j += 1;
            }
            let hash_start = j;
            while chars.get(j) == Some(&'#') {
                j += 1;
            }
            let hashes = j - hash_start;
            if raw && chars.get(j) == Some(&'"') {
                let mut k = j + 1;
                loop {
                    if k >= chars.len() {
                        break;
                    }
                    if chars[k] == '"'
                        && (1..=hashes).all(|offset| chars.get(k + offset) == Some(&'#'))
                    {
                        k += hashes + 1;
                        break;
                    }
                    k += 1;
                }
                for slot in in_literal.iter_mut().take(k.min(chars.len())).skip(i) {
                    *slot = true;
                }
                i = k;
                continue;
            }
        }

        // Ordinary (or byte) string literal.
        if c == '"' {
            let mut j = i;
            in_literal[j] = true;
            j += 1;
            while j < chars.len() {
                in_literal[j] = true;
                if chars[j] == '\\' {
                    if j + 1 < chars.len() {
                        in_literal[j + 1] = true;
                    }
                    j += 2;
                    continue;
                }
                if chars[j] == '"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            i = j;
            continue;
        }

        // Char literal — distinguished from a lifetime by its closing quote.
        if c == '\'' {
            let escaped = chars.get(i + 1) == Some(&'\\');
            if escaped || chars.get(i + 2) == Some(&'\'') {
                let mut j = i + 1;
                in_literal[i] = true;
                while j < chars.len() {
                    in_literal[j] = true;
                    if chars[j] == '\\' {
                        if j + 1 < chars.len() {
                            in_literal[j + 1] = true;
                        }
                        j += 2;
                        continue;
                    }
                    if chars[j] == '\'' {
                        j += 1;
                        break;
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
            i += 1;
            continue;
        }

        i += 1;
    }

    MaskedSource {
        chars: out,
        in_literal,
    }
}

/// Macro names whose arguments become log records, including sampled wrappers.
const TRACING_MACROS: [&str; 13] = [
    "trace",
    "debug",
    "info",
    "warn",
    "warn_sampled",
    "error",
    "event",
    "span",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
];

/// Byte ranges of the argument list of every tracing macro invocation.
fn tracing_argument_spans(masked: &MaskedSource) -> Vec<(usize, usize)> {
    let chars = &masked.chars;
    let mut spans = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] != '!' || masked.in_literal[i] {
            i += 1;
            continue;
        }
        // Macro name immediately before the `!` (path-qualified names such as
        // `tracing::warn!` reduce to their last segment).
        let mut name_start = i;
        while name_start > 0 && is_ident_char(chars[name_start - 1]) {
            name_start -= 1;
        }
        let name: String = chars[name_start..i].iter().collect();
        let mut open = i + 1;
        while open < chars.len() && chars[open].is_whitespace() {
            open += 1;
        }
        if !TRACING_MACROS.contains(&name.as_str()) || chars.get(open) != Some(&'(') {
            i += 1;
            continue;
        }

        let mut depth = 0usize;
        let mut j = open;
        let mut close = None;
        while j < chars.len() {
            if !masked.in_literal[j] {
                match chars[j] {
                    '(' | '[' | '{' => depth += 1,
                    ')' | ']' | '}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        let Some(close) = close else { break };
        spans.push((open + 1, close));
        i = close + 1;
    }

    spans
}

/// Top-level (comma-separated) argument ranges inside one invocation.
fn top_level_fields(masked: &MaskedSource, start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut field_start = start;
    let mut i = start;
    while i < end {
        if !masked.in_literal[i] {
            match masked.chars[i] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    fields.push((field_start, i));
                    field_start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    if field_start < end {
        fields.push((field_start, end));
    }
    fields
}

/// The range of the *value* a field records.
///
/// `name = expr` records `expr`; a shorthand field (`%key`, `?key`, `key`) and
/// a message/format argument record themselves. Only values are inspected, so
/// an innocuous value under a key-ish field name is not a false positive.
fn recorded_value_range(masked: &MaskedSource, start: usize, end: usize) -> (usize, usize) {
    let mut depth = 0usize;
    let mut i = start;
    while i < end {
        if !masked.in_literal[i] {
            match masked.chars[i] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                '=' if depth == 0 => {
                    let prev = masked.chars[start..i]
                        .iter()
                        .rev()
                        .find(|c| !c.is_whitespace())
                        .copied();
                    // `==`, `!=`, `<=`, `>=`, `=>` are operators, not a field
                    // assignment.
                    if matches!(prev, Some('=' | '!' | '<' | '>'))
                        || masked.chars.get(i + 1) == Some(&'=')
                        || masked.chars.get(i + 1) == Some(&'>')
                    {
                        i += 1;
                        continue;
                    }
                    let name: String = masked.chars[start..i].iter().collect();
                    let name = name.trim().trim_start_matches(['%', '?']);
                    let is_field_name = !name.is_empty()
                        && name
                            .chars()
                            .all(|c| is_ident_char(c) || c == '.' || c == ':')
                        && name.chars().next().is_some_and(|c| !c.is_ascii_digit());
                    if is_field_name {
                        return (i + 1, end);
                    }
                    return (start, end);
                }
                _ => {}
            }
        }
        i += 1;
    }
    (start, end)
}

/// Identifier tokens a value expression references, including inline format
/// captures (`"… {key} …"`). Literal *text* is otherwise ignored, so a message
/// that merely says "rate key" is not a finding.
fn value_expression_tokens(masked: &MaskedSource, start: usize, end: usize) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut i = start;

    while i < end {
        if masked.in_literal[i] {
            let literal_start = i;
            while i < end && masked.in_literal[i] {
                i += 1;
            }
            let text: String = masked.chars[literal_start..i].iter().collect();
            let bytes: Vec<char> = text.chars().collect();
            let mut k = 0usize;
            while k < bytes.len() {
                if bytes[k] == '{' {
                    if bytes.get(k + 1) == Some(&'{') {
                        k += 2;
                        continue;
                    }
                    if let Some(offset) = bytes[k + 1..].iter().position(|c| *c == '}') {
                        let inner: String = bytes[k + 1..k + 1 + offset].iter().collect();
                        let capture = inner.split(':').next().unwrap_or("").trim().to_string();
                        if !capture.is_empty()
                            && capture.chars().all(is_ident_char)
                            && !capture.chars().next().is_some_and(|c| c.is_ascii_digit())
                        {
                            tokens.push(capture);
                        }
                        k += offset + 2;
                        continue;
                    }
                }
                k += 1;
            }
            continue;
        }
        let c = masked.chars[i];
        if is_ident_char(c) {
            current.push(c);
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
        i += 1;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Documented operator configuration that merely *contains* "key" and carries no
/// enforcement identity.
const NON_IDENTITY_TOKENS: [&str; 4] = ["key_prefix", "key_prefixes", "contains_key", "keys"];

/// Identity-bearing value names that do not spell "key".
const IDENTITY_TOKENS: [&str; 8] = [
    "identity",
    "authenticated_identity",
    "consumer",
    "consumer_id",
    "principal",
    "spiffe_id",
    "client_ip",
    "peer_ip",
];

/// Whether an identifier used as a recorded value carries an enforcement
/// identity.
///
/// SCREAMING_SNAKE_CASE names are exempt: a compile-time constant is a fixed
/// string, so it cannot be a per-identity correlator however it is spelled.
fn is_identity_bearing_token(token: &str) -> bool {
    if token
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    if NON_IDENTITY_TOKENS.contains(&lower.as_str()) {
        return false;
    }
    lower == "key"
        || lower.ends_with("_key")
        || lower.starts_with("key_")
        || lower.contains("_key_")
        || IDENTITY_TOKENS.contains(&lower.as_str())
}

/// Every identity-bearing token recorded as a value by a tracing macro, with the
/// 1-based line of the field it appears in.
fn identity_bearing_log_values(source: &str) -> Vec<(usize, String, String)> {
    let masked = mask_source(source);
    let mut newline_offsets: Vec<usize> = Vec::new();
    for (index, c) in masked.chars.iter().enumerate() {
        if *c == '\n' {
            newline_offsets.push(index);
        }
    }
    let line_of = |index: usize| newline_offsets.partition_point(|nl| *nl < index) + 1;

    let mut findings = Vec::new();
    for (start, end) in tracing_argument_spans(&masked) {
        for (field_start, field_end) in top_level_fields(&masked, start, end) {
            let (value_start, value_end) = recorded_value_range(&masked, field_start, field_end);
            for token in value_expression_tokens(&masked, value_start, value_end) {
                if is_identity_bearing_token(&token) {
                    let field: String = masked.chars[field_start..field_end].iter().collect();
                    findings.push((
                        line_of(field_start),
                        token,
                        field.split_whitespace().collect::<Vec<_>>().join(" "),
                    ));
                }
            }
        }
    }
    findings
}

/// Number of tracing invocations the scanner recognized — a self-check that the
/// guard is actually reading these files rather than silently parsing nothing.
fn tracing_invocation_count(source: &str) -> usize {
    tracing_argument_spans(&mask_source(source)).len()
}

/// Static canary over the limiter surfaces that talk to the shared Redis client.
///
/// This is a canary, not a proof: it enforces one concrete boundary — no
/// identity-bearing identifier may appear in an expression a `tracing` macro
/// records as a value, in any field name, including shorthand fields, `%`/`?`
/// render forms, and inline format captures. Code that reaches a log through
/// something other than a literal tracing macro in these eight files (a helper
/// that formats a string elsewhere, a `Display` impl that embeds a key) is
/// outside what it can see.
#[test]
fn limiter_log_statements_never_carry_identity_bearing_keys() {
    for (path, source) in identity_log_guard_sources() {
        let findings = identity_bearing_log_values(source);
        assert!(
            findings.is_empty(),
            "{path} records identity-bearing values in tracing macros: {findings:?}"
        );
    }
}

/// The scanner must actually parse these files. Without this, a parser bug that
/// finds zero invocations would make the canary above pass vacuously forever.
#[test]
fn identity_log_guard_reads_every_governed_source() {
    for (path, source) in identity_log_guard_sources() {
        assert!(
            tracing_invocation_count(source) > 0,
            "{path}: the identity-log guard found no tracing macro invocations"
        );
    }

    // The known non-identity operator field must be *seen and allowed*, not
    // missed: it proves the scanner reaches real recorded values.
    let redis = include_str!("../../../src/plugins/utils/redis_rate_limiter.rs");
    let masked = mask_source(redis);
    let mut saw_key_prefix_value = false;
    for (start, end) in tracing_argument_spans(&masked) {
        for (field_start, field_end) in top_level_fields(&masked, start, end) {
            let (value_start, value_end) = recorded_value_range(&masked, field_start, field_end);
            if value_expression_tokens(&masked, value_start, value_end)
                .iter()
                .any(|token| token == "key_prefix")
            {
                saw_key_prefix_value = true;
            }
        }
    }
    assert!(
        saw_key_prefix_value,
        "the guard must reach `key_prefix = %self.config.key_prefix` and allow it"
    );
}

/// Bypass spellings the previous substring canary could not see, plus the
/// non-findings it must not flag.
#[test]
fn identity_log_guard_catches_arbitrary_field_names_and_render_forms() {
    let caught = [
        // Arbitrary field name — the whole point of the strengthening.
        r#"fn f() { warn!(anything_at_all = %key, "denied"); }"#,
        r#"fn f() { warn!(rate_key = %redis_key, "denied"); }"#,
        // Shorthand fields, both render sigils and the bare form.
        r#"fn f() { warn!(%key, "denied"); }"#,
        r#"fn f() { warn!(?redis_key, "denied"); }"#,
        r#"fn f() { warn!(curr_key, "denied"); }"#,
        // Expressions, not just bindings.
        r#"fn f() { info!(detail = ?self.make_redis_key(id), "x"); }"#,
        r#"fn f() { warn!(detail = %format!("{}", prev_key), "x"); }"#,
        // Digests and encodings are still per-identity correlators.
        r#"fn f() { warn!(fingerprint = %sha256(count_key), "x"); }"#,
        // Inline format captures in the message itself.
        r#"fn f() { debug!("window for {key} tripped"); }"#,
        // Path-qualified macro.
        r#"fn f() { tracing::warn!(field = %total_key, "x"); }"#,
        // Sampling wrappers retain the same recorded-value boundary.
        r#"fn f() { warn_sampled!(anything_at_all = %key, "denied"); }"#,
        r#"fn f() { warn_sampled!(?redis_key, "denied"); }"#,
        r#"fn f() { crate::warn_sampled!("window for {key} tripped"); }"#,
        // Identity values that do not spell "key".
        r#"fn f() { warn!(who = %authenticated_identity, "x"); }"#,
    ];
    for source in caught {
        assert!(
            !identity_bearing_log_values(source).is_empty(),
            "guard missed an identity-bearing log value: {source}"
        );
    }

    let allowed = [
        // Documented non-identity operator config.
        r#"fn f() { warn!(key_prefix = %self.config.key_prefix, "x"); }"#,
        r#"fn f() { warn_sampled!(key_prefix = %self.config.key_prefix, "x"); }"#,
        // Ordinary bindings and non-tracing macros are not log records.
        r#"fn f() { let previous_key = b(); assert!(!previous_key.is_empty()); }"#,
        r#"fn f() { panic!("{previous_key}"); }"#,
        r#"fn f() { let msg = format!("{count_key}"); }"#,
        // A message that merely *mentions* a key is text, not a recorded value.
        r#"fn f() { warn!(plugin = "rate_limiting", "rate key rejected"); }"#,
        // Commented-out code is not compiled and is not a log statement.
        "fn f() { /* warn!(rate_key = %key, \"x\"); */ }",
        "fn f() { // warn!(rate_key = %key, \"x\");\n }",
        // Compile-time constants cannot be per-identity correlators.
        r#"fn f() { debug!(marker = %AI_REQUEST_METADATA_KEY, "x"); }"#,
        // Field *names* alone are not values.
        r#"fn f() { warn!(redis_key_present = %flag, "x"); }"#,
    ];
    for source in allowed {
        assert!(
            identity_bearing_log_values(source).is_empty(),
            "guard produced a false positive: {source} -> {:?}",
            identity_bearing_log_values(source)
        );
    }
}
