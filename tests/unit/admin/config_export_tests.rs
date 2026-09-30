//! `GET /config/export` fingerprint projection (issue #5904).
//!
//! The export must fingerprint exactly the values the ordinary viewer / audit
//! projection withholds, never disclose a stored secret, and produce
//! fingerprints that are stable for an unchanged value and change with it.

use ferrum_edge::admin::config_export::{
    FINGERPRINT_PREFIX, FingerprintRendering, build_config_export, fingerprint_key,
    fingerprint_key_id,
};
use ferrum_edge::admin::plugin_config_projection::{
    project_plugin_config, project_plugin_config_with,
};
use ferrum_edge::config::types::{
    GatewayConfig, redact_consumer_credentials_for_audit,
    redact_consumer_credentials_for_audit_with,
};
use ferrum_edge::fips::approved::HmacSha256Key;
use serde_json::{Value, json};
use std::collections::BTreeSet;

const ADMIN_SECRET: &str = "config-export-admin-secret-0123456789";
const ROTATED_ADMIN_SECRET: &str = "config-export-rotated-admin-secret-0123";

const KEYAUTH_KEY: &str = "live-api-key-must-not-leak-0001";
const JWT_SECRET: &str = "jwt-consumer-secret-must-not-leak-0123456789";
const HMAC_SECRET: &str = "hmac-consumer-secret-must-not-leak-0123456789";
const PASSWORD_HASH: &str =
    "hmac_sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONSUL_TOKEN: &str = "consul-acl-token-must-not-leak";
const OTEL_AUTHORIZATION: &str = "Bearer otel-token-must-not-leak";
const HONEYCOMB_KEY: &str = "honeycomb-team-key-must-not-leak";
const ENDPOINT_QUERY_TOKEN: &str = "query-token-must-not-leak";
const REDIS_PASSWORD: &str = "redis-password-must-not-leak";

fn key(secret: &str) -> HmacSha256Key {
    fingerprint_key(secret).expect("a non-empty secret derives a key")
}

fn fixture(keyauth_key: &str) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "proxy-1",
            "listen_path": "/api",
            "backend_host": "backend.internal",
            "backend_port": 8080,
            "backend_scheme": "http"
        }],
        "consumers": [{
            "id": "consumer-1",
            "username": "alice",
            "credentials": {
                "keyauth": [{"key": keyauth_key}],
                "jwt": [{"secret": JWT_SECRET}],
                "hmac_auth": [{"secret": HMAC_SECRET}],
                "basicauth": [{"password_hash": PASSWORD_HASH}],
                "mtls_auth": [{"identity": "client.example.com"}]
            }
        }],
        "plugin_configs": [
            {
                "id": "otel",
                "plugin_name": "otel_tracing",
                "scope": "global",
                "enabled": false,
                "config": {
                    "endpoint": format!(
                        "https://collector.example.com/v1/traces?token={ENDPOINT_QUERY_TOKEN}"
                    ),
                    "authorization": OTEL_AUTHORIZATION,
                    "headers": {"x-honeycomb-team": HONEYCOMB_KEY},
                    "service_name": "edge-gateway"
                }
            },
            {
                "id": "rate-limit",
                "plugin_name": "rate_limiting",
                "scope": "global",
                "enabled": false,
                "config": {
                    "redis_url": format!("redis://:{REDIS_PASSWORD}@cache.internal:6379/2"),
                    "limit_by": "ip"
                }
            }
        ],
        "upstreams": [{
            "id": "upstream-1",
            "name": "orders",
            "targets": [],
            "service_discovery": {
                "provider": "consul",
                "consul": {
                    "address": "http://consul.internal:8500",
                    "service_name": "orders",
                    "token": CONSUL_TOKEN
                }
            }
        }]
    }))
    .expect("fixture deserializes")
}

fn is_lower_hex_digest(hex: &str) -> bool {
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_fingerprint(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|text| text.strip_prefix(FINGERPRINT_PREFIX))
        .is_some_and(is_lower_hex_digest)
}

fn export(config: GatewayConfig, secret: &str) -> Value {
    build_config_export(config, "cached", "ferrum", &key(secret))
}

#[test]
fn export_fingerprints_every_withheld_value_and_discloses_none() {
    let export = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);
    let text = export.to_string();
    for secret in [
        KEYAUTH_KEY,
        JWT_SECRET,
        HMAC_SECRET,
        PASSWORD_HASH,
        CONSUL_TOKEN,
        OTEL_AUTHORIZATION,
        HONEYCOMB_KEY,
        ENDPOINT_QUERY_TOKEN,
        REDIS_PASSWORD,
        ADMIN_SECRET,
    ] {
        assert!(
            !text.contains(secret),
            "export disclosed stored secret material: {secret}"
        );
    }

    let consumer = &export["consumers"][0];
    let credentials = &consumer["credentials"];
    assert!(is_fingerprint(&credentials["keyauth"][0]["key"]));
    assert!(is_fingerprint(&credentials["jwt"][0]["secret"]));
    assert!(is_fingerprint(&credentials["hmac_auth"][0]["secret"]));
    assert!(
        is_fingerprint(&credentials["basicauth"]),
        "basicauth is one opaque fingerprint, as in audit diffs: {credentials}"
    );
    let mtls = &credentials["mtls_auth"][0];
    assert_eq!(mtls["identity"], "client.example.com");
    assert_eq!(consumer["username"], "alice");

    let otel = &export["plugin_configs"][0]["config"];
    assert!(is_fingerprint(&otel["endpoint"]));
    assert!(is_fingerprint(&otel["authorization"]));
    assert!(is_fingerprint(&otel["headers"]["x-honeycomb-team"]));
    assert_eq!(otel["service_name"], "edge-gateway");
    let rate_limit = &export["plugin_configs"][1]["config"];
    assert!(is_fingerprint(&rate_limit["redis_url"]));
    assert_eq!(rate_limit["limit_by"], "ip");

    let consul = &export["upstreams"][0]["service_discovery"]["consul"];
    assert!(is_fingerprint(&consul["token"]));
    assert_eq!(consul["address"], "http://consul.internal:8500");

    let proxy = &export["proxies"][0];
    assert_eq!(proxy["backend_host"], "backend.internal");
    assert_eq!(export["source"], "cached");
    assert_eq!(export["namespace"], "ferrum");
    assert_eq!(export["counts"]["consumers"], 1);
    assert_eq!(export["counts"]["plugin_configs"], 2);
    let redaction = &export["redaction"];
    let expected_key_id = fingerprint_key_id(&key(ADMIN_SECRET));
    assert_eq!(redaction["fingerprint_key_id"], expected_key_id);
    assert_eq!(redaction["fingerprint_prefix"], FINGERPRINT_PREFIX);
}

#[test]
fn fingerprints_are_stable_for_unchanged_values() {
    let first = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);
    let second = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);
    for collection in ["proxies", "consumers", "plugin_configs", "upstreams"] {
        assert_eq!(
            first[collection], second[collection],
            "`{collection}` must compare equal across exports of unchanged config"
        );
    }

    // Canonical input: object key order does not change a fingerprint.
    let key = key(ADMIN_SECRET);
    let rendering = FingerprintRendering::new(&key, "plugin_config", "ferrum", "p1");
    let forward: Value = serde_json::from_str(r#"{"a":1,"b":{"c":2,"d":3}}"#).unwrap();
    let reverse: Value = serde_json::from_str(r#"{"b":{"d":3,"c":2},"a":1}"#).unwrap();
    let forward = rendering.fingerprint(&forward);
    assert_eq!(forward, rendering.fingerprint(&reverse));
}

#[test]
fn fingerprint_changes_when_the_stored_secret_changes() {
    let before = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);
    let after = export(fixture("rotated-api-key-0002"), ADMIN_SECRET);

    let before = &before["consumers"][0]["credentials"];
    let after = &after["consumers"][0]["credentials"];
    let key_before = &before["keyauth"][0]["key"];
    let key_after = &after["keyauth"][0]["key"];
    assert!(is_fingerprint(key_before) && is_fingerprint(key_after));
    assert_ne!(key_before, key_after, "rotated key must differ");

    // Unrelated credentials on the same consumer are unaffected.
    assert_eq!(before["jwt"], after["jwt"]);
}

#[test]
fn rotating_the_admin_secret_changes_every_fingerprint_and_the_key_id() {
    let original = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);
    let rotated = export(fixture(KEYAUTH_KEY), ROTATED_ADMIN_SECRET);
    for pointer in [
        "/consumers/0/credentials/jwt/0/secret",
        "/upstreams/0/service_discovery/consul/token",
        "/redaction/fingerprint_key_id",
    ] {
        let before = original.pointer(pointer);
        assert!(before.is_some(), "{pointer} must exist");
        assert_ne!(before, rotated.pointer(pointer), "{pointer} must change");
    }
    assert!(fingerprint_key("").is_none());
}

#[test]
fn fingerprints_are_bound_to_their_resource() {
    let key = key(ADMIN_SECRET);
    let value = json!("shared-secret-value");
    let base = FingerprintRendering::new(&key, "consumer", "ferrum", "a");
    let base = base.fingerprint(&value);
    for (kind, namespace, id) in [
        ("consumer", "ferrum", "b"),
        ("consumer", "other", "a"),
        ("upstream", "ferrum", "a"),
    ] {
        let other = FingerprintRendering::new(&key, kind, namespace, id);
        let other = other.fingerprint(&value);
        assert_ne!(
            base, other,
            "({kind}, {namespace}, {id}) must not share a fingerprint"
        );
    }
}

/// Walk the stored value, the ordinary placeholder projection, and the
/// fingerprint projection together: wherever the placeholder projection left a
/// value untouched the export must too, and wherever it withheld or rewrote one
/// the export must carry a fingerprint.
fn assert_fingerprints_track_placeholders(
    stored: &Value,
    placeholder: &Value,
    fingerprinted: &Value,
    path: &str,
) {
    if placeholder == stored {
        assert_eq!(
            fingerprinted, stored,
            "{path}: a visible value must stay verbatim"
        );
        return;
    }
    match (stored, placeholder) {
        (Value::Object(stored_map), Value::Object(placeholder_map))
            if stored_map.len() == placeholder_map.len()
                && stored_map.keys().all(|k| placeholder_map.contains_key(k)) =>
        {
            for (field, stored_child) in stored_map {
                assert_fingerprints_track_placeholders(
                    stored_child,
                    &placeholder_map[field],
                    &fingerprinted[field],
                    &format!("{path}.{field}"),
                );
            }
        }
        (Value::Array(stored_items), Value::Array(placeholder_items))
            if stored_items.len() == placeholder_items.len() =>
        {
            for (index, stored_item) in stored_items.iter().enumerate() {
                assert_fingerprints_track_placeholders(
                    stored_item,
                    &placeholder_items[index],
                    &fingerprinted[index],
                    &format!("{path}[{index}]"),
                );
            }
        }
        _ => assert!(
            is_fingerprint(fingerprinted),
            "{path}: a withheld value must be fingerprinted, got {fingerprinted}"
        ),
    }
}

#[test]
fn plugin_config_export_uses_the_viewer_projection_decisions() {
    let key = key(ADMIN_SECRET);
    for plugin in fixture(KEYAUTH_KEY).plugin_configs {
        let mut placeholder = plugin.config.clone();
        project_plugin_config(&plugin.plugin_name, &mut placeholder);
        let mut fingerprinted = plugin.config.clone();
        let rendering = FingerprintRendering::new(&key, "plugin_config", "ferrum", &plugin.id);
        project_plugin_config_with(&plugin.plugin_name, &mut fingerprinted, &rendering);
        assert_ne!(
            placeholder, plugin.config,
            "fixture must exercise redaction"
        );
        assert_fingerprints_track_placeholders(
            &plugin.config,
            &placeholder,
            &fingerprinted,
            &plugin.plugin_name,
        );
    }
}

#[test]
fn consumer_export_uses_the_audit_projection_decisions() {
    let key = key(ADMIN_SECRET);
    let consumer = fixture(KEYAUTH_KEY).consumers.remove(0);
    let placeholder = json!(redact_consumer_credentials_for_audit(&consumer));
    let rendering = FingerprintRendering::new(&key, "consumer", "ferrum", &consumer.id);
    let fingerprinted = redact_consumer_credentials_for_audit_with(&consumer, &rendering);
    let fingerprinted = json!(fingerprinted);

    fn walk(placeholder: &Value, fingerprinted: &Value, path: &str) {
        match (placeholder, fingerprinted) {
            (Value::String(marker), _) if marker == "[REDACTED]" => assert!(
                is_fingerprint(fingerprinted),
                "{path}: `[REDACTED]` must become a fingerprint, got {fingerprinted}"
            ),
            (Value::Object(left), Value::Object(right)) => {
                let left_keys: BTreeSet<&String> = left.keys().collect();
                let right_keys: BTreeSet<&String> = right.keys().collect();
                assert_eq!(
                    left_keys, right_keys,
                    "{path}: the export must not add or drop fields"
                );
                for (field, child) in left {
                    walk(child, &right[field], &format!("{path}.{field}"));
                }
            }
            (Value::Array(left), Value::Array(right)) => {
                assert_eq!(left.len(), right.len(), "{path}: entry count must match");
                for (index, child) in left.iter().enumerate() {
                    walk(child, &right[index], &format!("{path}[{index}]"));
                }
            }
            _ => assert_eq!(placeholder, fingerprinted, "{path}: visible value changed"),
        }
    }
    walk(&placeholder, &fingerprinted, "consumer");
}
