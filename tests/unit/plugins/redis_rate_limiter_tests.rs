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

/// Accept TCP, optionally delay, then answer every RESP array command with +OK.
///
/// Used to simulate a Redis endpoint whose protocol handshake is delayed after
/// TCP accept (the failure mode in issue #2310).
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
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    // Rough RESP command count: each top-level array
                                    // begins with '*'. Enough for CLIENT SETINFO pipelines.
                                    let commands = buf[..n].iter().filter(|&&b| b == b'*').count().max(1);
                                    let mut reply = Vec::new();
                                    for _ in 0..commands {
                                        reply.extend_from_slice(b"+OK\r\n");
                                    }
                                    if stream.write_all(&reply).await.is_err() {
                                        break;
                                    }
                                }
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

    // Redis path: prev bucket full (10), current has the candidate request (1).
    // At fraction 0.0 the old code always denied; with subsecond decay the mid-
    // window candidate is admitted.
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

#[test]
fn shared_consumers_use_same_window_progress_helper() {
    // rate_limiting, GraphQL type/named-operation limits, and grpc_method_router
    // per-method limits all reach check_http_windows_redis → window_progress.
    // Prove the shared helper (not a per-plugin copy) is what the test support
    // and live clock path expose.
    use ferrum_edge::_test_support::{redis_window_progress, redis_window_progress_at};
    use ferrum_edge::plugins::utils::redis_rate_limiter::RedisRateLimitClient;

    let at = redis_window_progress_at(Duration::from_millis(1_250), 1);
    let direct = RedisRateLimitClient::window_progress_at(Duration::from_millis(1_250), 1);
    assert_eq!(at, direct);
    assert!((at.elapsed_fraction - 0.25).abs() < 1e-12);

    let live = redis_window_progress(1);
    assert!(live.elapsed_fraction >= 0.0 && live.elapsed_fraction < 1.0);
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
                            for _ in 0..commands {
                                reply.extend_from_slice(b"+OK\r\n");
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
                            for _ in 0..commands {
                                reply.extend_from_slice(b"+OK\r\n");
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
/// the transaction and redirects the keyed commands queued inside it. Counts
/// accepted TCP connections and observed `INCR` commands.
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
/// [`InfoBehavior`]) and `GET` (always a nil bulk string). `info_delay` /
/// `get_delay` hold the corresponding reply *after* counting it, so a test can
/// land a concurrent topology rejection while that exact operation is in flight.
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

/// One RESP round trip of the limiter's sliding window: the client sends
/// `MULTI` / `GET` / `INCRBY` / `EXPIRE` / `EXEC` as a single pipeline, so a
/// well-formed answer is `+OK`, three `+QUEUED`s, and the `EXEC` array.
const TRANSACTION_PREAMBLE: &[u8] = b"+OK\r\n+QUEUED\r\n+QUEUED\r\n+QUEUED\r\n";
/// `EXEC` array for a first-request window: `GET` nil, `INCRBY` → 1, `EXPIRE` → 1.
const TRANSACTION_SUCCESS: &[u8] = b"*3\r\n$-1\r\n:1\r\n:1\r\n";
/// A plain (non-Cluster) server error on `EXEC` — the ordinary retryable
/// failure a recycled socket produces, not a topology proof.
const TRANSACTION_FAILURE: &[u8] = b"-ERR simulated transient backend failure\r\n";
const MULTI_CMD: &[u8] = b"$5\r\nMULTI\r\n";

struct TransactionServer {
    port: u16,
    shutdown: oneshot::Sender<()>,
    accepts: Arc<AtomicUsize>,
    transactions: Arc<AtomicUsize>,
}

/// Screens clean on every connection, fails the FIRST sliding-window
/// transaction with a plain server error, and answers every later transaction
/// normally.
async fn spawn_first_transaction_fails_redis_server() -> TransactionServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local_addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let transactions = Arc::new(AtomicUsize::new(0));
    let accepts_task = Arc::clone(&accepts);
    let transactions_task = Arc::clone(&transactions);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    accepts_task.fetch_add(1, Ordering::Relaxed);
                    let transactions = Arc::clone(&transactions_task);
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let n = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            let chunk = &buf[..n];
                            let mut reply: Vec<u8> = Vec::new();
                            if chunk_contains(chunk, INFO_CMD) {
                                let text = "# Cluster\r\ncluster_enabled:0\r\n";
                                let len = text.len();
                                reply.extend_from_slice(
                                    format!("${len}\r\n{text}\r\n").as_bytes(),
                                );
                            } else if chunk_contains(chunk, MULTI_CMD) {
                                let index = transactions.fetch_add(1, Ordering::Relaxed);
                                reply.extend_from_slice(TRANSACTION_PREAMBLE);
                                if index == 0 {
                                    reply.extend_from_slice(TRANSACTION_FAILURE);
                                } else {
                                    reply.extend_from_slice(TRANSACTION_SUCCESS);
                                }
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

    TransactionServer {
        port,
        shutdown: shutdown_tx,
        accepts,
        transactions,
    }
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

    let server = spawn_first_transaction_fails_redis_server().await;
    let accepts = Arc::clone(&server.accepts);
    let transactions = Arc::clone(&server.transactions);

    let backend: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm> =
        RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": format!("redis://127.0.0.1:{}/0", server.port),
                "redis_pool_size": 1,
                // Long enough that neither the client's recovery checker nor the
                // failover observer can tick during this test: every transition
                // below is one this test performs explicitly.
                "redis_health_check_interval_seconds": 3600,
            }),
            &PluginHttpClient::default(),
            DynamicHttpRateLimitAlgorithm::new(),
        )
        .expect("failover backend");
    assert_eq!(
        backend.redis_failure_policy(),
        Some(RedisFailurePolicy::FailClosed),
        "this coverage is about the fail-closed default's recovery latency"
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
