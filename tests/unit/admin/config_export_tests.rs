//! `GET /config/export` fingerprint projection (issue #5904).
//!
//! The export must fingerprint exactly the values the ordinary viewer
//! projection withholds, never disclose a stored secret, and produce
//! fingerprints that are stable for an unchanged value, change with it, and are
//! bound to the field they stand for.

use ferrum_edge::admin::config_export::{
    FINGERPRINT_PREFIX, FingerprintRendering, HIDDEN_CREDENTIALS_FIELD, build_config_export,
    export_consumer, fingerprint_key, fingerprint_key_id,
};
use ferrum_edge::admin::plugin_config_projection::{
    project_plugin_config, project_plugin_config_with,
};
use ferrum_edge::config::types::{
    Consumer, GatewayConfig, redact_consumer_credentials, redact_consumer_credentials_with,
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
const CUSTOM_TOKEN: &str = "custom-credential-must-not-leak";
const CONSUL_TOKEN: &str = "consul-acl-token-must-not-leak";
const CONSUL_PASSWORD: &str = "consul-userinfo-password-must-not-leak";
const LABEL_PASSWORD: &str = "proxy-label-password-must-not-leak";
const OTEL_AUTHORIZATION: &str = "Bearer otel-token-must-not-leak";
const HONEYCOMB_KEY: &str = "honeycomb-team-key-must-not-leak";
const ENDPOINT_QUERY_TOKEN: &str = "query-token-must-not-leak";
const REDIS_PASSWORD: &str = "redis-password-must-not-leak";
const KAFKA_PASSWORD: &str = "kafka-sasl-password-must-not-leak";
const SLACK_WEBHOOK: &str = "https://hooks.slack.com/services/T000/B000/slack-token-must-not-leak";
const RAW_CONFIG: &str = "scalar-config-must-not-leak";
const TRIGGER_HEADER: &str = "trigger-header-operand-must-not-leak";
const TRIGGER_QUERY: &str = "trigger-query-operand-must-not-leak";
const EXT_AUTHZ_PREFIX: &str = "/check/ext-authz-prefix-must-not-leak";

fn key(secret: &str) -> HmacSha256Key {
    fingerprint_key(secret).expect("a non-empty secret derives a key")
}

/// Fixed timestamps, so two builds of the fixture are the same configuration.
const STAMP: &str = "2026-01-02T03:04:05Z";

fn fixture(keyauth_key: &str) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "proxy-1",
            "listen_path": "/api",
            "backend_host": "backend.internal",
            "backend_port": 8080,
            "backend_scheme": "http",
            "labels": {
                "runbook": format!("https://ops:{LABEL_PASSWORD}@wiki.internal/runbook")
            },
            "created_at": STAMP,
            "updated_at": STAMP
        }],
        "consumers": [{
            "id": "consumer-1",
            "username": "alice",
            "credentials": {
                "keyauth": [{"key": keyauth_key}],
                "jwt": [{"secret": JWT_SECRET}],
                "hmac_auth": [{"secret": HMAC_SECRET}],
                "basicauth": [{"password_hash": PASSWORD_HASH}],
                "mtls_auth": [{"identity": "client.example.com"}],
                "custom_auth": [{"api_token": CUSTOM_TOKEN}]
            },
            "created_at": STAMP,
            "updated_at": STAMP
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
                    "headers": {"x-honeycomb-team": HONEYCOMB_KEY, "x-copy": HONEYCOMB_KEY},
                    "service_name": "edge-gateway"
                },
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "rate-limit",
                "plugin_name": "rate_limiting",
                "scope": "global",
                "enabled": false,
                "config": {
                    "redis_url": format!("redis://:{REDIS_PASSWORD}@cache.internal:6379/2"),
                    "limit_by": "ip"
                },
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "kafka",
                "plugin_name": "kafka_logging",
                "scope": "global",
                "enabled": false,
                "config": {
                    "topic": "access",
                    "producer_config": {"acks": "all", "sasl.password": KAFKA_PASSWORD}
                },
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "alerts",
                "plugin_name": "proxy_alerts",
                "scope": "global",
                "enabled": false,
                "config": {
                    "channels": [
                        {"type": "slack", "webhook_url": SLACK_WEBHOOK},
                        {"type": "webhook", "url": "https://alerts.example.com/hook"}
                    ]
                },
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "scalar",
                "plugin_name": "custom_thing",
                "scope": "global",
                "enabled": false,
                "config": RAW_CONFIG,
                "created_at": STAMP,
                "updated_at": STAMP
            }
        ],
        "upstreams": [{
            "id": "upstream-1",
            "name": "orders",
            "targets": [],
            "service_discovery": {
                "provider": "consul",
                "consul": {
                    "address": format!("http://acl:{CONSUL_PASSWORD}@consul.internal:8500"),
                    "service_name": "orders",
                    "token": CONSUL_TOKEN
                }
            },
            "created_at": STAMP,
            "updated_at": STAMP
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

fn credential_types(consumer: &Value) -> BTreeSet<String> {
    consumer["credentials"]
        .as_object()
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default()
}

fn export(config: GatewayConfig, secret: &str) -> Value {
    build_config_export(config, "cached", "ferrum", &key(secret))
}

fn plugin<'a>(export: &'a Value, id: &str) -> &'a Value {
    export["plugin_configs"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == id))
        .unwrap_or_else(|| panic!("plugin config {id} exported"))
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
        CUSTOM_TOKEN,
        CONSUL_TOKEN,
        CONSUL_PASSWORD,
        LABEL_PASSWORD,
        OTEL_AUTHORIZATION,
        HONEYCOMB_KEY,
        ENDPOINT_QUERY_TOKEN,
        REDIS_PASSWORD,
        KAFKA_PASSWORD,
        SLACK_WEBHOOK,
        RAW_CONFIG,
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
    let mtls = &credentials["mtls_auth"][0];
    assert_eq!(mtls["identity"], "client.example.com");
    assert_eq!(consumer["username"], "alice");

    let otel = &plugin(&export, "otel")["config"];
    assert!(is_fingerprint(&otel["endpoint"]));
    assert!(is_fingerprint(&otel["authorization"]));
    assert!(is_fingerprint(&otel["headers"]["x-honeycomb-team"]));
    assert_eq!(otel["service_name"], "edge-gateway");
    let rate_limit = &plugin(&export, "rate-limit")["config"];
    assert!(is_fingerprint(&rate_limit["redis_url"]));
    assert_eq!(rate_limit["limit_by"], "ip");

    let consul = &export["upstreams"][0]["service_discovery"]["consul"];
    assert!(is_fingerprint(&consul["token"]));
    assert!(
        is_fingerprint(&consul["address"]),
        "a Consul address carrying userinfo must not be exported raw: {consul}"
    );
    assert_eq!(consul["service_name"], "orders");

    let proxy = &export["proxies"][0];
    assert_eq!(proxy["backend_host"], "backend.internal");
    assert!(is_fingerprint(&proxy["labels"]["runbook"]));
    assert_eq!(export["source"], "cached");
    assert_eq!(export["namespace"], "ferrum");
    assert_eq!(export["counts"]["consumers"], 1);
    assert_eq!(export["counts"]["plugin_configs"], 5);
    let redaction = &export["redaction"];
    let expected_key_id = fingerprint_key_id(&key(ADMIN_SECRET));
    assert_eq!(redaction["fingerprint_key_id"], expected_key_id);
    assert_eq!(redaction["fingerprint_prefix"], FINGERPRINT_PREFIX);
}

#[test]
fn export_of_unchanged_config_is_byte_identical() {
    let config = fixture(KEYAUTH_KEY);
    let first = serde_json::to_vec(&export(config.clone(), ADMIN_SECRET)).unwrap();
    let second = serde_json::to_vec(&export(config, ADMIN_SECRET)).unwrap();
    assert_eq!(first, second, "unchanged config must export identically");

    // Two independent builds of the same stored configuration agree too.
    let rebuilt = serde_json::to_vec(&export(fixture(KEYAUTH_KEY), ADMIN_SECRET)).unwrap();
    assert_eq!(first, rebuilt);

    // Canonical input: object key order does not change a fingerprint.
    let key = key(ADMIN_SECRET);
    let rendering = FingerprintRendering::new(&key, "plugin_config", "ferrum", "p1");
    let forward: Value = serde_json::from_str(r#"{"a":1,"b":{"c":2,"d":3}}"#).unwrap();
    let reverse: Value = serde_json::from_str(r#"{"b":{"d":3,"c":2},"a":1}"#).unwrap();
    let forward = rendering.fingerprint("/config/x", &forward);
    assert_eq!(forward, rendering.fingerprint("/config/x", &reverse));
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
        "/consumers/0/hidden_credentials_fingerprint",
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
fn fingerprints_are_bound_to_their_resource_and_field() {
    let key = key(ADMIN_SECRET);
    let value = json!("shared-secret-value");
    let base = FingerprintRendering::new(&key, "consumer", "ferrum", "a");
    let base = base.fingerprint("/credentials/jwt/0/secret", &value);
    for (kind, namespace, id, pointer) in [
        ("consumer", "ferrum", "b", "/credentials/jwt/0/secret"),
        ("consumer", "other", "a", "/credentials/jwt/0/secret"),
        ("upstream", "ferrum", "a", "/credentials/jwt/0/secret"),
        ("consumer", "ferrum", "a", "/credentials/hmac_auth/0/secret"),
        ("consumer", "ferrum", "a", "/credentials/jwt/1/secret"),
    ] {
        let other = FingerprintRendering::new(&key, kind, namespace, id);
        let other = other.fingerprint(pointer, &value);
        assert_ne!(
            base, other,
            "({kind}, {namespace}, {id}, {pointer}) must not share a fingerprint"
        );
    }

    // The same stored value in two fields of one export fingerprints apart.
    let mut config = fixture(KEYAUTH_KEY);
    let credentials = &mut config.consumers[0].credentials;
    credentials.insert("jwt".to_string(), json!([{"secret": "same-value"}]));
    credentials.insert("hmac_auth".to_string(), json!([{"secret": "same-value"}]));
    let export = export(config, ADMIN_SECRET);
    let credentials = &export["consumers"][0]["credentials"];
    assert_ne!(
        credentials["jwt"][0]["secret"],
        credentials["hmac_auth"][0]["secret"]
    );
    let headers = &plugin(&export, "otel")["config"]["headers"];
    assert!(is_fingerprint(&headers["x-copy"]));
    assert_ne!(headers["x-honeycomb-team"], headers["x-copy"]);
}

#[test]
fn a_field_matched_by_several_layers_is_fingerprinted_once() {
    // `authorization` is both an `otel_tracing` schema secret and a
    // name-heuristic match; the export carries the fingerprint of the stored
    // value itself, not a fingerprint of a fingerprint.
    let key = key(ADMIN_SECRET);
    let export = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);
    let rendering = FingerprintRendering::new(&key, "plugin_config", "ferrum", "otel");
    let expected = rendering.fingerprint("/config/authorization", &json!(OTEL_AUTHORIZATION));
    let otel = &plugin(&export, "otel")["config"];
    assert_eq!(otel["authorization"], expected);

    let rendering = FingerprintRendering::new(&key, "plugin_config", "ferrum", "alerts");
    let stored = json!(SLACK_WEBHOOK);
    let expected = rendering.fingerprint("/config/channels/0/webhook_url", &stored);
    let channels = &plugin(&export, "alerts")["config"]["channels"];
    assert_eq!(channels[0]["webhook_url"], expected);
}

#[test]
fn kafka_properties_arrays_and_scalar_configs_follow_the_projection() {
    let export = export(fixture(KEYAUTH_KEY), ADMIN_SECRET);

    let kafka = &plugin(&export, "kafka")["config"];
    assert_eq!(kafka["topic"], "access");
    assert_eq!(kafka["producer_config"]["acks"], "all");
    assert!(is_fingerprint(&kafka["producer_config"]["sasl.password"]));

    let channels = &plugin(&export, "alerts")["config"]["channels"];
    assert_eq!(channels[0]["type"], "slack");
    assert!(is_fingerprint(&channels[0]["webhook_url"]));
    assert_eq!(channels[1]["type"], "webhook");

    // No built-in plugin accepts a scalar config: the whole value is withheld.
    assert!(is_fingerprint(&plugin(&export, "scalar")["config"]));
}

#[test]
fn consumer_export_matches_viewer_reads_and_hides_the_presence_of_omitted_types() {
    let key = key(ADMIN_SECRET);
    let consumer = fixture(KEYAUTH_KEY).consumers.remove(0);
    let exported = export_consumer(&consumer, &key);

    // Ordinary viewer reads omit `basicauth` and custom types; so does the
    // export's credential map.
    let viewer = json!(redact_consumer_credentials(&consumer));
    assert_eq!(credential_types(&exported), credential_types(&viewer));
    assert!(exported["credentials"].get("basicauth").is_none());
    assert!(exported["credentials"].get("custom_auth").is_none());

    // Hidden types are summarized by one fingerprint that changes with them.
    let hidden = &exported[HIDDEN_CREDENTIALS_FIELD];
    assert!(is_fingerprint(hidden));
    let mut changed_basic = consumer.clone();
    let basic = json!([{"password_hash": format!("hmac_sha256:{}", "b".repeat(64))}]);
    changed_basic
        .credentials
        .insert("basicauth".to_string(), basic);
    let changed_basic = export_consumer(&changed_basic, &key);
    assert_ne!(hidden, &changed_basic[HIDDEN_CREDENTIALS_FIELD]);
    let mut changed_custom = consumer.clone();
    changed_custom
        .credentials
        .insert("custom_auth".to_string(), json!([{"api_token": "rotated"}]));
    let changed_custom = export_consumer(&changed_custom, &key);
    assert_ne!(hidden, &changed_custom[HIDDEN_CREDENTIALS_FIELD]);

    // A consumer with no hidden credentials still carries the field, so its
    // presence reveals nothing, and its visible credentials are unchanged.
    let mut visible_only = consumer.clone();
    visible_only.credentials.remove("basicauth");
    visible_only.credentials.remove("custom_auth");
    let visible_only = export_consumer(&visible_only, &key);
    assert!(is_fingerprint(&visible_only[HIDDEN_CREDENTIALS_FIELD]));
    assert_eq!(visible_only["credentials"], exported["credentials"]);
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
        project_plugin_config_with(
            &plugin.plugin_name,
            &mut fingerprinted,
            "/config",
            &rendering,
        );
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
fn consumer_export_uses_the_viewer_projection_decisions() {
    let key = key(ADMIN_SECRET);
    let consumer: Consumer = fixture(KEYAUTH_KEY).consumers.remove(0);
    let placeholder = json!(redact_consumer_credentials(&consumer));
    let rendering = FingerprintRendering::new(&key, "consumer", "ferrum", &consumer.id);
    let fingerprinted = redact_consumer_credentials_with(&consumer, &rendering);
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

#[test]
fn legacy_single_object_credentials_use_the_emitted_index() {
    let key = key(ADMIN_SECRET);
    let mut consumer: Consumer = fixture(KEYAUTH_KEY).consumers.remove(0);
    consumer
        .credentials
        .insert("jwt".to_string(), json!({"secret": JWT_SECRET}));
    let exported = export_consumer(&consumer, &key);

    let rendering = FingerprintRendering::new(&key, "consumer", "ferrum", &consumer.id);
    let expected = rendering.fingerprint("/credentials/jwt/0/secret", &json!(JWT_SECRET));
    assert_eq!(exported["credentials"]["jwt"][0]["secret"], expected);

    // A non-object entry is dropped before indexing: the surviving entry is
    // emitted at index 0, and its pointer says so.
    consumer
        .credentials
        .insert("jwt".to_string(), json!([null, {"secret": JWT_SECRET}]));
    let exported = export_consumer(&consumer, &key);
    assert_eq!(exported["credentials"]["jwt"][0]["secret"], expected);
}

#[test]
fn export_fingerprints_request_transformer_rule_values() {
    let key = key(ADMIN_SECRET);
    let rendering = FingerprintRendering::new(&key, "plugin_config", "ferrum", "rt");
    let mut config = json!({
        "rules": [
            {"operation": "update", "target": "header", "key": "Authorization",
             "value": "Bearer rt-export-canary"},
            {"operation": "add", "target": "query", "key": "token",
             "value": "rt-export-query-canary"}
        ]
    });
    project_plugin_config_with("request_transformer", &mut config, "/config", &rendering);
    let text = config.to_string();
    assert!(!text.contains("rt-export-canary"), "{text}");
    assert!(!text.contains("rt-export-query-canary"), "{text}");
    assert!(is_fingerprint(&config["rules"][0]["value"]));
    assert!(is_fingerprint(&config["rules"][1]["value"]));
    assert_eq!(config["rules"][1]["target"], "query");
}

/// A plugin `trigger` (a sibling of `config`) is exported through the same
/// projection: its header, query and cookie operands are fingerprinted at any
/// depth of the tree, while field names, match kinds and structure are
/// exported verbatim.
#[test]
fn export_fingerprints_plugin_trigger_operands() {
    let mut config = fixture(KEYAUTH_KEY);
    let triggered: ferrum_edge::config::types::PluginConfig = serde_json::from_value(json!({
        "id": "triggered",
        "plugin_name": "stdout_logging",
        "scope": "global",
        "enabled": false,
        "config": {},
        "trigger": {"when": {"any": [
            {"not": {"match": {"header": {
                "name": "x-skip",
                "value": {"exact": [TRIGGER_HEADER]}
            }}}},
            {"match": {"query": {"name": "debug", "value": {"regex": TRIGGER_QUERY}}}},
            {"match": {"method": ["POST"]}}
        ]}},
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("trigger fixture");
    config.plugin_configs.push(triggered);

    let export = export(config, ADMIN_SECRET);
    let any = &plugin(&export, "triggered")["trigger"]["when"]["any"];
    let header = &any[0]["not"]["match"]["header"];
    assert_eq!(header["name"], "x-skip");
    assert!(is_fingerprint(&header["value"]["exact"][0]), "{header}");
    let query = &any[1]["match"]["query"];
    assert_eq!(query["name"], "debug");
    assert!(is_fingerprint(&query["value"]["regex"]), "{query}");
    assert_eq!(any[2]["match"]["method"], json!(["POST"]));
    let text = export.to_string();
    for secret in [TRIGGER_HEADER, TRIGGER_QUERY] {
        assert!(!text.contains(secret), "export leaked {secret}");
    }
}

/// A `mesh_authz` external-authorization `path_prefix` is fingerprinted in the
/// export, while the provider's name, service, and port are exported verbatim.
#[test]
fn export_fingerprints_mesh_authz_ext_authz_path_prefix() {
    let mut config = fixture(KEYAUTH_KEY);
    let mesh_authz: ferrum_edge::config::types::PluginConfig = serde_json::from_value(json!({
        "id": "mesh-authz",
        "plugin_name": "mesh_authz",
        "scope": "global",
        "enabled": false,
        "config": {"mesh_slice": {"ext_authz_providers": [{
            "name": "ext-check",
            "service": "authz.shop.svc.cluster.local",
            "port": 9000,
            "path_prefix": EXT_AUTHZ_PREFIX
        }]}},
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("mesh_authz fixture");
    config.plugin_configs.push(mesh_authz);

    let export = export(config, ADMIN_SECRET);
    let slice = &plugin(&export, "mesh-authz")["config"]["mesh_slice"];
    let provider = &slice["ext_authz_providers"][0];
    assert!(is_fingerprint(&provider["path_prefix"]), "{provider}");
    assert_eq!(provider["name"], "ext-check");
    assert_eq!(provider["service"], "authz.shop.svc.cluster.local");
    assert_eq!(provider["port"], 9000);
    assert!(!export.to_string().contains(EXT_AUTHZ_PREFIX));
}

const INLINE_CLIENT_CERT: &str =
    "-----BEGIN CERTIFICATE-----\nY2xpZW50LWNlcnQ=\n-----END CERTIFICATE-----\n";
const INLINE_CLIENT_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\na2V5LW11c3Qtbm90LWxlYWs=\n-----END PRIVATE KEY-----\n";
const INLINE_CLIENT_KEY_BODY: &str = "a2V5LW11c3Qtbm90LWxlYWs=";

fn backend_tls_fixture() -> GatewayConfig {
    let bundle = format!("{INLINE_CLIENT_CERT}{INLINE_CLIENT_KEY}");
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [
            {
                "id": "proxy-inline",
                "listen_path": "/inline",
                "backend_host": "backend.internal",
                "backend_port": 8443,
                "backend_scheme": "https",
                "backend_tls_client_cert_path": INLINE_CLIENT_CERT,
                "backend_tls_client_key_path": INLINE_CLIENT_KEY,
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "proxy-reference",
                "listen_path": "/reference",
                "backend_host": "backend.internal",
                "backend_port": 8443,
                "backend_scheme": "https",
                "backend_tls_client_cert_path": "k8s://ferrum/client-mtls#tls.crt",
                "backend_tls_client_key_path": "k8s://ferrum/client-mtls#tls.key",
                "created_at": STAMP,
                "updated_at": STAMP
            }
        ],
        "plugin_configs": [],
        "upstreams": [
            {
                "id": "upstream-inline",
                "name": "inline",
                "targets": [],
                "backend_tls_client_cert_path": INLINE_CLIENT_CERT,
                "backend_tls_client_key_path": INLINE_CLIENT_KEY,
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "upstream-bundle",
                "name": "bundle",
                "targets": [],
                "backend_tls_client_cert_path": bundle,
                "backend_tls_client_key_path": "/etc/ferrum/backend/client.key",
                "created_at": STAMP,
                "updated_at": STAMP
            },
            {
                "id": "upstream-mesh",
                "name": "mesh",
                "targets": [],
                "subsets": [{
                    "name": "v1",
                    "labels": {"version": "v1"},
                    "traffic_policy": {"tls": {
                        "mode": "mutual",
                        "client_certificate": INLINE_CLIENT_CERT,
                        "private_key": INLINE_CLIENT_KEY,
                        "ca_certificates": "k8s://ferrum/v1-mtls#ca.crt"
                    }}
                }],
                "port_overrides": {
                    "443": {"tls": {
                        "client_cert_path": INLINE_CLIENT_CERT,
                        "client_key_path": INLINE_CLIENT_KEY
                    }},
                    "8443": {"tls": {
                        "client_cert_path": "k8s://ferrum/p8443#tls.crt",
                        "client_key_path": "k8s://ferrum/p8443#tls.key"
                    }}
                },
                "created_at": STAMP,
                "updated_at": STAMP
            }
        ]
    }))
    .expect("backend TLS fixture deserializes")
}

fn exported<'a>(export: &'a Value, collection: &str, id: &str) -> &'a Value {
    export[collection]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == id))
        .unwrap_or_else(|| panic!("{collection} {id} exported"))
}

/// Inline backend TLS private keys on proxies and upstreams are withheld by the
/// viewer projection, so the export fingerprints them; references and public
/// certificates are shown verbatim.
#[test]
fn export_fingerprints_inline_backend_tls_private_keys_and_keeps_references() {
    let key = key(ADMIN_SECRET);
    let export = build_config_export(backend_tls_fixture(), "cached", "ferrum", &key);
    let text = export.to_string();
    assert!(!text.contains("PRIVATE KEY"), "{text}");
    assert!(!text.contains(INLINE_CLIENT_KEY_BODY), "{text}");

    let proxy = exported(&export, "proxies", "proxy-inline");
    let rendering = FingerprintRendering::new(&key, "proxy", "ferrum", "proxy-inline");
    let pointer = "/backend_tls_client_key_path";
    let expected = rendering.fingerprint(pointer, &json!(INLINE_CLIENT_KEY));
    assert_eq!(proxy["backend_tls_client_key_path"], expected);
    assert_eq!(proxy["backend_tls_client_cert_path"], INLINE_CLIENT_CERT);
    assert_eq!(proxy["backend_host"], "backend.internal");

    let proxy = exported(&export, "proxies", "proxy-reference");
    assert_eq!(
        proxy["backend_tls_client_key_path"],
        "k8s://ferrum/client-mtls#tls.key"
    );
    assert_eq!(
        proxy["backend_tls_client_cert_path"],
        "k8s://ferrum/client-mtls#tls.crt"
    );

    let inline = exported(&export, "upstreams", "upstream-inline");
    assert!(is_fingerprint(&inline["backend_tls_client_key_path"]));
    assert_eq!(inline["backend_tls_client_cert_path"], INLINE_CLIENT_CERT);
    assert_eq!(inline["name"], "inline");

    // A certificate field carrying a private-key block is withheld as well.
    let upstream = exported(&export, "upstreams", "upstream-bundle");
    assert!(is_fingerprint(&upstream["backend_tls_client_cert_path"]));
    assert_eq!(
        upstream["backend_tls_client_key_path"],
        "/etc/ferrum/backend/client.key"
    );

    // Nested subset and per-port TLS slots are fingerprinted at their exact
    // pointers; references and certificates beside them stay verbatim.
    let mesh = exported(&export, "upstreams", "upstream-mesh");
    let rendering = FingerprintRendering::new(&key, "upstream", "ferrum", "upstream-mesh");
    for pointer in [
        "/subsets/0/traffic_policy/tls/private_key",
        "/port_overrides/443/tls/client_key_path",
    ] {
        let expected = rendering.fingerprint(pointer, &json!(INLINE_CLIENT_KEY));
        assert_eq!(mesh.pointer(pointer), Some(&json!(expected)), "{pointer}");
    }
    let at = |pointer: &str| mesh.pointer(pointer).cloned().unwrap_or_default();
    assert_eq!(
        at("/subsets/0/traffic_policy/tls/client_certificate"),
        INLINE_CLIENT_CERT
    );
    assert_eq!(
        at("/subsets/0/traffic_policy/tls/ca_certificates"),
        "k8s://ferrum/v1-mtls#ca.crt"
    );
    assert_eq!(
        at("/port_overrides/443/tls/client_cert_path"),
        INLINE_CLIENT_CERT
    );
    assert_eq!(
        at("/port_overrides/8443/tls/client_key_path"),
        "k8s://ferrum/p8443#tls.key"
    );
}

/// A certificate-plus-key bundle in a plugin certificate source is
/// fingerprinted exactly like the Proxy and Upstream TLS fields, while a
/// certificate-only CA source and a key reference are exported verbatim.
#[test]
fn export_fingerprints_plugin_certificate_plus_key_bundles() {
    let mut config = fixture(KEYAUTH_KEY);
    let bundle = format!("{INLINE_CLIENT_CERT}{INLINE_CLIENT_KEY}");
    let udp: ferrum_edge::config::types::PluginConfig = serde_json::from_value(json!({
        "id": "udp-dtls",
        "plugin_name": "udp_logging",
        "scope": "global",
        "enabled": false,
        "config": {
            "host": "logs.internal",
            "dtls": true,
            "dtls_cert_path": bundle,
            "dtls_key_path": "k8s://ferrum/udp-client#tls.key",
            "dtls_ca_cert_path": INLINE_CLIENT_CERT
        },
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("udp_logging fixture");
    config.plugin_configs.push(udp);

    let export = export(config, ADMIN_SECRET);
    let udp = &plugin(&export, "udp-dtls")["config"];
    assert!(is_fingerprint(&udp["dtls_cert_path"]), "{udp}");
    assert_eq!(udp["dtls_ca_cert_path"], INLINE_CLIENT_CERT);
    assert_eq!(udp["dtls_key_path"], "k8s://ferrum/udp-client#tls.key");
    assert!(!export.to_string().contains(INLINE_CLIENT_KEY_BODY));
}

/// An `opa_host` base path is fingerprinted in the export; `policy_path`
/// stays verbatim.
#[test]
fn export_fingerprints_opa_host_base_path() {
    let mut config = fixture(KEYAUTH_KEY);
    let opa: ferrum_edge::config::types::PluginConfig = serde_json::from_value(json!({
        "id": "opa",
        "plugin_name": "opa",
        "scope": "global",
        "enabled": false,
        "config": {
            "opa_host": "https://opa.example.com/opa-base-path-must-not-leak",
            "policy_path": "/v1/data/authz/allow"
        },
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("opa fixture");
    config.plugin_configs.push(opa);

    let export = export(config, ADMIN_SECRET);
    let opa = &plugin(&export, "opa")["config"];
    assert!(is_fingerprint(&opa["opa_host"]), "{opa}");
    assert_eq!(opa["policy_path"], "/v1/data/authz/allow");
    assert!(!export.to_string().contains("opa-base-path-must-not-leak"));
}

/// A custom plugin cannot be classified, so every scalar leaf of its config is
/// fingerprinted in the export; keys and `null` stay verbatim.
#[test]
fn export_fingerprints_every_custom_plugin_scalar_leaf() {
    let mut config = fixture(KEYAUTH_KEY);
    let custom: ferrum_edge::config::types::PluginConfig = serde_json::from_value(json!({
        "id": "custom-object",
        "plugin_name": "third_party_custom_plugin",
        "scope": "global",
        "enabled": false,
        "config": {
            "auth_headers": [{"name": "X-Vendor-Token", "value": "custom-pair-must-not-leak"}],
            "account_id": 987654321,
            "note": null
        },
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("custom plugin fixture");
    config.plugin_configs.push(custom);

    let export = export(config, ADMIN_SECRET);
    let custom = &plugin(&export, "custom-object")["config"];
    let pair = &custom["auth_headers"][0];
    assert!(is_fingerprint(&pair["name"]), "{custom}");
    assert!(is_fingerprint(&pair["value"]), "{custom}");
    assert!(is_fingerprint(&custom["account_id"]), "{custom}");
    assert_eq!(custom["note"], Value::Null);
    assert!(!export.to_string().contains("custom-pair-must-not-leak"));
}

/// A `request_mirror` shadow path is fingerprinted in the export like an
/// endpoint URL path; the host, port, and protocol stay verbatim.
#[test]
fn export_fingerprints_request_mirror_path() {
    let mut config = fixture(KEYAUTH_KEY);
    let mirror: ferrum_edge::config::types::PluginConfig = serde_json::from_value(json!({
        "id": "mirror",
        "plugin_name": "request_mirror",
        "scope": "global",
        "enabled": false,
        "config": {
            "mirror_host": "shadow.internal",
            "mirror_port": 8443,
            "mirror_protocol": "https",
            "mirror_path": "/ingest/mirror-path-must-not-leak"
        },
        "created_at": STAMP,
        "updated_at": STAMP
    }))
    .expect("request_mirror fixture");
    config.plugin_configs.push(mirror);

    let export = export(config, ADMIN_SECRET);
    let mirror = &plugin(&export, "mirror")["config"];
    assert!(is_fingerprint(&mirror["mirror_path"]), "{mirror}");
    assert_eq!(mirror["mirror_host"], "shadow.internal");
    assert_eq!(mirror["mirror_port"], 8443);
    assert_eq!(mirror["mirror_protocol"], "https");
    assert!(!export.to_string().contains("mirror-path-must-not-leak"));
}
