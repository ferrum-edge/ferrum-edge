//! Schema-aware plugin-configuration sensitivity contract
//! (GHSA-4988-2wph-67g2).
//!
//! These cover the projection itself. The role/audit/backup surfaces that
//! consume it are covered end to end in
//! `tests/integration/admin_audit_rbac_tests.rs`.

use ferrum_edge::admin::plugin_config_projection::{
    KAFKA_SAFE_PRODUCER_PROPERTIES, PLUGIN_SENSITIVITY_SCHEMAS, PlaceholderSiteRecorder,
    is_credential_bearing_url_config_key, is_redaction_placeholder,
    is_safe_kafka_producer_property, is_sensitive_plugin_config_key, normalize_config_key,
    project_plugin_config, project_plugin_config_with, redact_endpoint_url, sensitivity_rules_for,
};
use ferrum_edge::plugins::builtin_parity::BUILTIN_PLUGIN_PARITY_META;
use serde_json::{Value, json};

const REDACTED: &str = "[REDACTED]";

fn project(plugin: &str, config: Value) -> Value {
    let mut projected = config;
    project_plugin_config(plugin, &mut projected);
    projected
}

/// Assert none of `canaries` survives anywhere in the projected document.
fn assert_no_canaries(projected: &Value, canaries: &[&str]) {
    let serialized = projected.to_string();
    for canary in canaries {
        assert!(
            !serialized.contains(canary),
            "projection leaked {canary}: {serialized}"
        );
    }
}

// ---------------------------------------------------------------------------
// Future built-in parity
// ---------------------------------------------------------------------------

/// A new built-in plugin must not be able to ship without an explicit
/// sensitivity decision. This is the gate that keeps the contract exhaustive
/// instead of drifting back into name guessing.
#[test]
fn every_builtin_plugin_has_a_sensitivity_schema_entry() {
    let missing: Vec<&str> = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .map(|meta| meta.name)
        .filter(|name| {
            !PLUGIN_SENSITIVITY_SCHEMAS
                .iter()
                .any(|(schema_name, _)| schema_name == name)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "built-in plugins without a sensitivity schema entry (add one to \
         PLUGIN_SENSITIVITY_SCHEMAS, using the empty rule set if nothing in the \
         plugin's config is credential-bearing): {missing:?}"
    );
}

/// The reverse direction: a schema entry for a plugin that no longer exists is
/// dead weight that hides a real gap behind a passing parity test.
#[test]
fn sensitivity_schema_has_no_entries_for_unknown_plugins() {
    let unknown: Vec<&str> = PLUGIN_SENSITIVITY_SCHEMAS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| {
            !BUILTIN_PLUGIN_PARITY_META
                .iter()
                .any(|meta| meta.name == *name)
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "sensitivity schema entries for unknown plugins: {unknown:?}"
    );
}

#[test]
fn sensitivity_schema_has_no_duplicate_plugin_entries() {
    let mut names: Vec<&str> = PLUGIN_SENSITIVITY_SCHEMAS.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate plugin entries in schema");
}

#[test]
fn unknown_custom_plugins_get_no_schema_rules_but_still_project() {
    assert!(sensitivity_rules_for("some_custom_plugin").is_empty());

    let projected = project(
        "some_custom_plugin",
        json!({
            "api_key": "custom-plugin-api-key-canary",
            "sink_url": "https://user:custom-plugin-userinfo-canary@sink.example.com/ingest",
            "batch_size": 50
        }),
    );
    // Heuristic layer still fires for custom plugins.
    assert_eq!(projected["api_key"], REDACTED);
    // Structural URL sweep still strips userinfo on a path no rule names.
    assert_eq!(
        projected["sink_url"],
        "https://redacted@sink.example.com/ingest"
    );
    // Safe-value control: ordinary tuning survives.
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(
        &projected,
        &[
            "custom-plugin-api-key-canary",
            "custom-plugin-userinfo-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Structural URL projection
// ---------------------------------------------------------------------------

#[test]
fn endpoint_url_projection_keeps_only_origin_and_structural_markers() {
    assert_eq!(
        redact_endpoint_url("https://user:pw@collector.example.com:4318/v1/traces?k=v#frag"),
        "https://redacted@collector.example.com:4318/[REDACTED_PATH]?[REDACTED_QUERY]#[REDACTED_FRAGMENT]"
    );
    // Userinfo gets its own marker even when the URL has no other suffix.
    assert_eq!(
        redact_endpoint_url("https://user:pw@collector.example.com"),
        "https://redacted@collector.example.com"
    );
    // Without userinfo or suffix components, the origin alone is emitted.
    assert_eq!(
        redact_endpoint_url("https://collector.example.com"),
        "https://collector.example.com"
    );
    assert_eq!(
        redact_endpoint_url("https://collector.example.com/"),
        "https://collector.example.com"
    );
    // IPv6 literals keep their brackets so the value stays a parseable origin.
    assert_eq!(
        redact_endpoint_url("https://[2001:db8::1]:8443/ingest"),
        "https://[2001:db8::1]:8443/[REDACTED_PATH]"
    );
    // Non-HTTP schemes are projected the same way.
    assert_eq!(
        redact_endpoint_url("ldaps://ldap.example.com:636/dc=example"),
        "ldaps://ldap.example.com:636/[REDACTED_PATH]"
    );
}

#[test]
fn endpoint_url_projection_fails_closed_for_unparseable_and_hostless_values() {
    assert_eq!(redact_endpoint_url("not a url at all"), REDACTED);
    assert_eq!(redact_endpoint_url(""), REDACTED);
    // No host to anchor the diagnostic on.
    assert_eq!(redact_endpoint_url("mailto:ops@example.com"), REDACTED);
}

// ---------------------------------------------------------------------------
// Advisory-named surfaces
// ---------------------------------------------------------------------------

#[test]
fn serverless_function_keys_and_trigger_urls_are_projected() {
    let projected = project(
        "serverless_function",
        json!({
            "provider": "azure_functions",
            "function_url": "https://fn.example.net/api/serverless-path-canary?code=serverless-query-canary",
            "azure_function_key": "serverless-function-key-canary",
            "timeout_ms": 3000
        }),
    );
    assert_eq!(
        projected["function_url"],
        "https://fn.example.net/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["azure_function_key"], REDACTED);
    assert_eq!(projected["timeout_ms"], 3000);
    assert_eq!(projected["provider"], "azure_functions");
    assert_no_canaries(
        &projected,
        &[
            "serverless-path-canary",
            "serverless-query-canary",
            "serverless-function-key-canary",
        ],
    );
}

#[test]
fn http_logging_endpoint_and_every_custom_header_value_are_projected() {
    let projected = project(
        "http_logging",
        json!({
            "endpoint_url": "https://collector.example.com/ingest/http-path-canary?key=http-query-canary",
            "custom_headers": {
                // No substring pattern matches this vendor header name.
                "x-honeycomb-team": "http-header-canary",
                "X-Tenant": "http-tenant-canary"
            },
            "batch_size": 50
        }),
    );
    assert_eq!(
        projected["endpoint_url"],
        "https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["custom_headers"]["x-honeycomb-team"], REDACTED);
    assert_eq!(projected["custom_headers"]["X-Tenant"], REDACTED);
    // Header NAMES stay visible; only values are secret.
    assert!(
        projected["custom_headers"]
            .as_object()
            .expect("headers object")
            .contains_key("x-honeycomb-team")
    );
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(
        &projected,
        &[
            "http-path-canary",
            "http-query-canary",
            "http-header-canary",
            "http-tenant-canary",
        ],
    );
}

#[test]
fn otel_header_values_are_secret_by_default_regardless_of_name() {
    let projected = project(
        "otel_tracing",
        json!({
            "endpoint": "https://api.honeycomb.io/v1/traces",
            "headers": {
                "x-honeycomb-team": "otel-honeycomb-canary",
                "dd-api-key": "otel-datadog-canary",
                "lightstep-access-token": "otel-lightstep-canary",
                "x-tenant": "otel-tenant-canary"
            },
            "batch_size": 50,
            "include_url_path": true
        }),
    );
    for name in [
        "x-honeycomb-team",
        "dd-api-key",
        "lightstep-access-token",
        "x-tenant",
    ] {
        assert_eq!(projected["headers"][name], REDACTED, "header {name}");
    }
    assert_eq!(projected["batch_size"], 50);
    assert_eq!(projected["include_url_path"], true);
    assert_no_canaries(
        &projected,
        &[
            "otel-honeycomb-canary",
            "otel-datadog-canary",
            "otel-lightstep-canary",
            "otel-tenant-canary",
        ],
    );
}

#[test]
fn proxy_alerts_generic_webhook_url_headers_and_body_template_are_projected() {
    let projected = project(
        "proxy_alerts",
        json!({
            "channels": {
                "generic": {
                    "type": "webhook",
                    // Generic key `url`, not `webhook_url`: no substring match.
                    "url": "https://hooks.example.com/services/alerts-path-canary?t=alerts-query-canary",
                    "headers": {
                        "x-routing-key": "alerts-header-canary"
                    },
                    "body_template": "{\"routing_key\":\"alerts-template-canary\",\"msg\":\"${message}\"}",
                    "method": "POST"
                },
                "ops-slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/services/T0/B0/alerts-slack-canary"
                }
            },
            "rules": [{"name": "5xx", "type": "error_rate", "threshold": 5}]
        }),
    );
    let generic = &projected["channels"]["generic"];
    assert_eq!(
        generic["url"],
        "https://hooks.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(generic["headers"]["x-routing-key"], REDACTED);
    assert_eq!(generic["body_template"], REDACTED);
    // Safe-value controls: channel type/method and rules stay readable.
    assert_eq!(generic["type"], "webhook");
    assert_eq!(generic["method"], "POST");
    assert_eq!(projected["rules"][0]["name"], "5xx");
    assert_eq!(projected["rules"][0]["threshold"], 5);
    // The name-heuristic layer already fully redacts `webhook_url`; the schema
    // must not weaken that to a structural projection.
    assert_eq!(projected["channels"]["ops-slack"]["webhook_url"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "alerts-path-canary",
            "alerts-query-canary",
            "alerts-header-canary",
            "alerts-template-canary",
            "alerts-slack-canary",
        ],
    );
}

#[test]
fn proxy_alerts_array_shaped_channels_are_projected_too() {
    let projected = project(
        "proxy_alerts",
        json!({
            "channels": [
                {
                    "type": "webhook",
                    "url": "https://hooks.example.com/array-path-canary",
                    "headers": {"x-routing-key": "array-header-canary"},
                    "body_template": "array-template-canary"
                }
            ]
        }),
    );
    assert_eq!(
        projected["channels"][0]["url"],
        "https://hooks.example.com/[REDACTED_PATH]"
    );
    assert_eq!(
        projected["channels"][0]["headers"]["x-routing-key"],
        REDACTED
    );
    assert_eq!(projected["channels"][0]["body_template"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "array-path-canary",
            "array-header-canary",
            "array-template-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Kafka producer properties
// ---------------------------------------------------------------------------

#[test]
fn kafka_producer_properties_redact_everything_outside_the_safe_allow_list() {
    let projected = project(
        "kafka_logging",
        json!({
            "broker_list": "broker.example.com:9093",
            "topic": "ferrum-logs",
            "security_protocol": "sasl_ssl",
            "producer_config": {
                // librdkafka marks each of these sensitive.
                "ssl.key.pem": "-----BEGIN PRIVATE KEY-----kafka-pem-canary-----END PRIVATE KEY-----",
                "ssl.key.password": "kafka-keypw-canary",
                "ssl.keystore.password": "kafka-keystorepw-canary",
                "sasl.password": "kafka-saslpw-canary",
                "sasl.oauthbearer.config": "kafka-oauth-canary",
                // Matches no name heuristic at all: only the allow-list saves it.
                "sasl.kerberos.keytab": "kafka-keytab-canary",
                // Safe tuning knobs survive as operator diagnostics.
                "linger.ms": "20",
                "compression.type": "lz4",
                "queue.buffering.max.messages": "100000"
            }
        }),
    );
    let props = &projected["producer_config"];
    for sensitive in [
        "ssl.key.pem",
        "ssl.key.password",
        "ssl.keystore.password",
        "sasl.password",
        "sasl.oauthbearer.config",
        "sasl.kerberos.keytab",
    ] {
        assert_eq!(props[sensitive], REDACTED, "property {sensitive}");
    }
    assert_eq!(props["linger.ms"], "20");
    assert_eq!(props["compression.type"], "lz4");
    assert_eq!(props["queue.buffering.max.messages"], "100000");
    assert_eq!(projected["topic"], "ferrum-logs");
    assert_eq!(projected["broker_list"], "broker.example.com:9093");
    assert_no_canaries(
        &projected,
        &[
            "kafka-pem-canary",
            "kafka-keypw-canary",
            "kafka-keystorepw-canary",
            "kafka-saslpw-canary",
            "kafka-oauth-canary",
            "kafka-keytab-canary",
        ],
    );
}

/// The allow-list is the load-bearing half of the Kafka rule: a stray entry
/// silently un-redacts a property forever.
#[test]
fn kafka_safe_property_allow_list_holds_no_credential_shaped_names() {
    for safe in KAFKA_SAFE_PRODUCER_PROPERTIES {
        for marker in [
            "password", "secret", "key", "pem", "token", "cert", "auth", "sasl", "ssl",
        ] {
            assert!(
                !safe.contains(marker),
                "allow-listed producer property {safe} contains credential marker {marker}"
            );
        }
    }
    assert!(is_safe_kafka_producer_property("LINGER.MS"));
    assert!(is_safe_kafka_producer_property(" linger.ms "));
    assert!(!is_safe_kafka_producer_property("ssl.key.pem"));
    assert!(!is_safe_kafka_producer_property("sasl.oauthbearer.config"));
    assert!(!is_safe_kafka_producer_property("sasl.kerberos.keytab"));
}

#[test]
fn kafka_non_object_producer_config_fails_closed() {
    let projected = project(
        "kafka_logging",
        json!({"producer_config": "kafka-scalar-canary"}),
    );
    assert_eq!(projected["producer_config"], REDACTED);
    assert_no_canaries(&projected, &["kafka-scalar-canary"]);
}

// ---------------------------------------------------------------------------
// Shape handling: nesting, arrays, case/delimiter variants, fail-closed
// ---------------------------------------------------------------------------

#[test]
fn normalize_config_key_equates_case_delimiter_and_compact_spellings() {
    let expected = "customheaders";
    for spelling in [
        "custom_headers",
        "custom-headers",
        "customHeaders",
        "CUSTOM_HEADERS",
        "custom.headers",
        "customheaders",
        "CUSTOMHEADERS",
        "Custom_Headers",
    ] {
        assert_eq!(
            normalize_config_key(spelling),
            expected,
            "spelling {spelling} did not compact to {expected}"
        );
    }

    // Exact normalized matching: nearby safe spellings stay distinct.
    assert_ne!(normalize_config_key("custom_headers_enabled"), expected);
    assert_ne!(normalize_config_key("customheader"), expected);
    assert_ne!(normalize_config_key("headers"), expected);
    assert_eq!(normalize_config_key("redisUrl"), "redisurl");
    assert_eq!(normalize_config_key("redis_url"), "redisurl");
    assert_eq!(normalize_config_key("endpointUrl"), "endpointurl");
    assert_ne!(normalize_config_key("redis_username"), "redisurl");
}

#[test]
fn schema_paths_match_case_and_delimiter_variants() {
    for spelling in [
        "custom_headers",
        "custom-headers",
        "customHeaders",
        "CUSTOM_HEADERS",
        "custom.headers",
        "customheaders",
    ] {
        let mut config = serde_json::Map::new();
        config.insert(
            spelling.to_string(),
            json!({"x-scope-orgid": "loki-variant-canary"}),
        );
        // Safe sibling that must not collapse onto the sensitive map rule.
        config.insert("custom_headers_enabled".to_string(), json!(true));
        config.insert("batch_size".to_string(), json!(10));
        let projected = project("loki_logging", Value::Object(config));
        assert_eq!(
            projected[spelling]["x-scope-orgid"], REDACTED,
            "spelling {spelling} bypassed the schema"
        );
        assert_eq!(projected["custom_headers_enabled"], true);
        assert_eq!(projected["batch_size"], 10);
        assert_no_canaries(&projected, &["loki-variant-canary"]);
    }
}

/// CamelCase / compact spellings must match schema paths at every depth, for
/// both arbitrary header-value maps and structural URL leaves.
#[test]
fn camelcase_and_compact_schema_paths_redact_at_nested_depths() {
    // Nested sink map: camelCase container + camelCase URL leaf.
    let projected = project(
        "ai_transcript_audit",
        json!({
            "sink": {
                "type": "http",
                "endpointUrl": "https://audit.example.com/ingest/nested-url-canary?token=nested-query-canary",
                "customHeaders": {"X-Audit-Token": "nested-header-canary"},
                "batch_size": 25
            },
            // Flat legacy aliases under compact spellings.
            "customheaders": {"Authorization": "flat-header-canary"},
            "endpointurl": "https://audit.example.com/flat-url-canary"
        }),
    );
    assert_eq!(
        projected["sink"]["endpointUrl"],
        "https://audit.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(
        projected["sink"]["customHeaders"]["X-Audit-Token"],
        REDACTED
    );
    assert_eq!(projected["customheaders"]["Authorization"], REDACTED);
    assert_eq!(
        projected["endpointurl"],
        "https://audit.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["sink"]["type"], "http");
    assert_eq!(projected["sink"]["batch_size"], 25);
    assert_no_canaries(
        &projected,
        &[
            "nested-url-canary",
            "nested-query-canary",
            "nested-header-canary",
            "flat-header-canary",
            "flat-url-canary",
        ],
    );

    // OTel headers map under compact spelling; endpoint under camelCase.
    let projected = project(
        "otel_tracing",
        json!({
            "endpoint": "https://otel.example.com/v1/traces/otel-path-canary",
            "Headers": {"x-honeycomb-team": "otel-header-canary"},
            "service_name": "edge"
        }),
    );
    assert_eq!(
        projected["endpoint"],
        "https://otel.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["Headers"]["x-honeycomb-team"], REDACTED);
    assert_eq!(projected["service_name"], "edge");
    assert_no_canaries(&projected, &["otel-path-canary", "otel-header-canary"]);
}

/// Unrelated safe fields must not normalize onto a sensitive schema segment.
#[test]
fn normalization_does_not_collapse_safe_fields_onto_sensitive_rules() {
    let projected = project(
        "http_logging",
        json!({
            "endpoint_url": "https://logs.example.com/ingest/http-path-canary",
            "custom_headers": {"X-Api-Key": "http-header-canary"},
            // Nearby names that share a prefix/suffix with sensitive segments.
            "custom_headers_enabled": true,
            "customheader": "safe-customheader-value",
            "headers_count": 3,
            "endpoint_url_timeout_ms": 1500,
            "batch_size": 50
        }),
    );
    assert_eq!(
        projected["endpoint_url"],
        "https://logs.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["custom_headers"]["X-Api-Key"], REDACTED);
    assert_eq!(projected["custom_headers_enabled"], true);
    assert_eq!(projected["customheader"], "safe-customheader-value");
    assert_eq!(projected["headers_count"], 3);
    assert_eq!(projected["endpoint_url_timeout_ms"], 1500);
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(&projected, &["http-path-canary", "http-header-canary"]);
}

/// Direct heuristic / Redis-URL callers must honor the compact normalization.
#[test]
fn heuristic_and_redis_url_callers_match_compact_normalized_spellings() {
    for spelling in [
        "api_key", "api-key", "apiKey", "API_KEY", "api.key", "apikey",
    ] {
        assert!(
            is_sensitive_plugin_config_key(spelling),
            "heuristic missed sensitive spelling {spelling}"
        );
    }
    for spelling in [
        "redis_integrity_key",
        "redisIntegrityKey",
        "redisintegritykey",
        "client_secret",
        "clientSecret",
        "azure_function_key",
        "service_account_json",
        "serviceAccountJson",
    ] {
        assert!(
            is_sensitive_plugin_config_key(spelling),
            "heuristic missed sensitive spelling {spelling}"
        );
    }
    // Negative controls: safe neighbors must not trip the substring floor.
    assert!(!is_sensitive_plugin_config_key("batch_size"));
    assert!(!is_sensitive_plugin_config_key("redis_username"));
    assert!(!is_sensitive_plugin_config_key("integrity_status"));
    assert!(!is_sensitive_plugin_config_key("ttl_seconds"));
    assert!(!is_sensitive_plugin_config_key("api_version"));
    assert!(!is_sensitive_plugin_config_key("keyboard_layout"));

    for spelling in [
        "redis_url",
        "redis-url",
        "redisUrl",
        "REDIS_URL",
        "redis.url",
        "redisurl",
    ] {
        assert!(
            is_credential_bearing_url_config_key(spelling),
            "redis URL detector missed spelling {spelling}"
        );
    }
    assert!(!is_credential_bearing_url_config_key("redis_username"));
    assert!(!is_credential_bearing_url_config_key("redis_url_template"));
    assert!(!is_credential_bearing_url_config_key("url"));

    // End-to-end through the heuristic layer on a custom plugin (no schema).
    let projected = project(
        "some_custom_plugin",
        json!({
            "apiKey": "custom-apikey-canary",
            "redisUrl": "redis://cacheuser:custom-redis-canary@cache.internal:6379/2",
            "redisUsername": "cacheuser",
            "batchSize": 9
        }),
    );
    assert_eq!(projected["apiKey"], REDACTED);
    assert_eq!(
        projected["redisUrl"],
        "redis://redacted@cache.internal:6379/2"
    );
    assert_eq!(projected["redisUsername"], "cacheuser");
    assert_eq!(projected["batchSize"], 9);
    assert_no_canaries(&projected, &["custom-apikey-canary", "custom-redis-canary"]);
}

#[test]
fn nested_and_array_wrapped_endpoint_values_fail_closed() {
    // A header map that is not a map cannot be classified per-entry.
    let projected = project(
        "otel_tracing",
        json!({"headers": "otel-scalar-headers-canary"}),
    );
    assert_eq!(projected["headers"], REDACTED);
    assert_no_canaries(&projected, &["otel-scalar-headers-canary"]);

    // An endpoint that is an array of nested objects is replaced wholesale
    // rather than walked, so a credential at any depth cannot survive.
    let projected = project(
        "otel_tracing",
        json!({"endpoint": [null, {"nested": "https://c.example/x?code=otel-nested-canary"}]}),
    );
    assert_eq!(projected["endpoint"], REDACTED);
    assert_no_canaries(&projected, &["otel-nested-canary"]);
}

#[test]
fn null_values_are_preserved_and_null_config_is_untouched() {
    let projected = project(
        "otel_tracing",
        json!({"endpoint": null, "authorization": null, "headers": null}),
    );
    assert!(projected["endpoint"].is_null());
    assert!(projected["authorization"].is_null());
    assert!(projected["headers"].is_null());

    let mut null_config = Value::Null;
    project_plugin_config("otel_tracing", &mut null_config);
    assert!(null_config.is_null());
}

#[test]
fn non_object_configs_are_replaced_wholesale() {
    for shape in [
        json!("scalar-config-canary"),
        json!(["array-config-canary", {"nested": "nested-config-canary"}]),
        json!(42),
        json!(true),
    ] {
        let projected = project("loki_logging", shape);
        assert_eq!(projected, json!(REDACTED));
    }
}

#[test]
fn url_userinfo_is_stripped_on_paths_no_rule_names() {
    let projected = project(
        "mcp_gateway",
        json!({
            // Not in any rule for this plugin.
            "discovery": {
                "peers": [
                    "https://svc:userinfo-array-canary@peer.example.com/mcp",
                    "https://plain.example.com/mcp"
                ]
            },
            "upstream_url": "https://svc:upstream-userinfo-canary@up.example.com/mcp"
        }),
    );
    assert_eq!(
        projected["discovery"]["peers"][0],
        "https://redacted@peer.example.com/mcp"
    );
    // Safe-value control: a URL without userinfo is untouched by the sweep.
    assert_eq!(
        projected["discovery"]["peers"][1],
        "https://plain.example.com/mcp"
    );
    // The schema rule wins on the named path: userinfo is marked and the path
    // is replaced with its structural marker.
    assert_eq!(
        projected["upstream_url"],
        "https://redacted@up.example.com/[REDACTED_PATH]"
    );
    assert_no_canaries(
        &projected,
        &["userinfo-array-canary", "upstream-userinfo-canary"],
    );
}

/// Header *name* lists are not credentials. Redacting them would break routing
/// configuration readability and is exactly the mistake a substring-only rule
/// makes.
#[test]
fn header_name_lists_are_not_redacted() {
    let projected = project(
        "cors",
        json!({
            "allowed_headers": ["authorization", "content-type"],
            "exposed_headers": ["x-request-id"]
        }),
    );
    assert_eq!(
        projected["allowed_headers"],
        json!(["authorization", "content-type"])
    );
    assert_eq!(projected["exposed_headers"], json!(["x-request-id"]));

    let projected = project(
        "rate_limiting",
        json!({"expose_headers": true, "limit_by": "ip"}),
    );
    assert_eq!(projected["expose_headers"], true);
    assert_eq!(projected["limit_by"], "ip");
}

/// The documented Redis projection shape must survive the refactor: it is
/// pinned by `docs/admin_api.md` and matches the Redis client's log fields.
#[test]
fn redis_url_keeps_its_documented_projection_shape() {
    let projected = project(
        "rate_limiting",
        json!({
            "redis_url": "redis://cacheuser:redis-userinfo-canary@cache.internal:6379/3?token=redis-query-canary#redis-frag-canary",
            "redis_username": "cacheuser",
            "sync_mode": "redis"
        }),
    );
    assert_eq!(
        projected["redis_url"],
        "redis://redacted@cache.internal:6379/3?[REDACTED_QUERY]#[REDACTED_FRAGMENT]"
    );
    // `redis_username` is not secret material and stays visible.
    assert_eq!(projected["redis_username"], "cacheuser");
    assert_eq!(projected["sync_mode"], "redis");
    assert_no_canaries(
        &projected,
        &[
            "redis-userinfo-canary",
            "redis-query-canary",
            "redis-frag-canary",
        ],
    );
}

#[test]
fn redis_projection_placeholders_are_detected_at_the_masked_site() {
    for (raw_url, expected) in [
        ("redis://redacted@h:6379/0", "redis://redacted@h:6379/0"),
        (
            "redis://h:6379/0?[REDACTED_QUERY]",
            "redis://h:6379/0?[REDACTED_QUERY]",
        ),
    ] {
        let mut config = json!({"redis_url": raw_url, "sync_mode": "redis"});
        let recorder = PlaceholderSiteRecorder::default();
        project_plugin_config_with("rate_limiting", &mut config, "/config", &recorder);
        assert_eq!(config["redis_url"], expected);
        assert_eq!(recorder.into_sites(), vec!["/config/redis_url".to_string()]);
        assert!(is_redaction_placeholder(&config["redis_url"]));
    }
}

/// `workload_metrics` accepts the same tracing-provider endpoint families as
/// the standalone tracing path. Their path/query components can carry
/// collector credentials, so both its singleton compatibility shape and its
/// canonical provider list must be covered by the schema.
#[test]
fn workload_metrics_tracing_provider_endpoints_are_projected_in_both_shapes() {
    let singleton = project(
        "workload_metrics",
        json!({
            "tracing_provider": {
                "kind": "zipkin",
                "config": {
                    "url": "https://zipkin.example.com/api/v2/workload-singleton-canary?token=singleton-query-canary"
                }
            },
            "service_name": "checkout"
        }),
    );
    assert_eq!(
        singleton["tracing_provider"]["config"]["url"],
        "https://zipkin.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(singleton["tracing_provider"]["kind"], "zipkin");
    assert_eq!(singleton["service_name"], "checkout");
    assert_no_canaries(
        &singleton,
        &["workload-singleton-canary", "singleton-query-canary"],
    );

    let providers = project(
        "workload_metrics",
        json!({
            "tracing_providers": [
                {
                    "kind": "zipkin",
                    "config": {
                        "url": "https://zipkin.example.com/api/v2/list-zipkin-canary"
                    }
                },
                {
                    "kind": "datadog",
                    "config": {
                        "agent_url": "https://datadog.example.com/list-datadog-canary?key=datadog-query-canary",
                        "service": "payments"
                    }
                },
                {
                    "kind": "lightstep",
                    "config": {
                        "collector_url": "https://lightstep.example.com/list-lightstep-canary?token=lightstep-query-canary"
                    }
                },
                {
                    "kind": "opentelemetry",
                    "config": {
                        "endpoint": "https://otel.example.com/v1/list-otel-canary?key=otel-query-canary"
                    }
                }
            ],
            "span_reporting_disabled": false
        }),
    );
    for (idx, expected) in [
        "https://zipkin.example.com/[REDACTED_PATH]",
        "https://datadog.example.com/[REDACTED_PATH]?[REDACTED_QUERY]",
        "https://lightstep.example.com/[REDACTED_PATH]?[REDACTED_QUERY]",
        "https://otel.example.com/[REDACTED_PATH]?[REDACTED_QUERY]",
    ]
    .into_iter()
    .enumerate()
    {
        let key = match idx {
            0 => "url",
            1 => "agent_url",
            2 => "collector_url",
            _ => "endpoint",
        };
        assert_eq!(providers["tracing_providers"][idx]["config"][key], expected);
    }
    assert_eq!(
        providers["tracing_providers"][1]["config"]["service"],
        "payments"
    );
    assert_eq!(providers["span_reporting_disabled"], false);
    assert_no_canaries(
        &providers,
        &[
            "list-zipkin-canary",
            "list-datadog-canary",
            "datadog-query-canary",
            "list-lightstep-canary",
            "lightstep-query-canary",
            "list-otel-canary",
            "otel-query-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Wildcard entry semantics over array-shaped containers
// ---------------------------------------------------------------------------

/// A `*` segment names *each entry of the container*. Over an array the entries
/// are the elements themselves, so the segment must be consumed at the array
/// rather than handed to each element's own fields — otherwise the remaining
/// path (`base_url`) resolves against sibling scalars and fail-closes every
/// non-credential provider field the schema never named.
#[test]
fn array_shaped_provider_entries_keep_their_non_credential_fields() {
    let projected = project(
        "ai_federation",
        json!({
            "providers": [{
                "name": "redaction-provider",
                "provider_type": "openai",
                "api_key": "federation-provider-api-key-canary",
                "base_url": "https://api.example.com/v1/federation-base-canary",
                "model_patterns": ["gpt-*"]
            }]
        }),
    );
    let provider = &projected["providers"][0];
    // The credential-bearing paths are still projected...
    assert_eq!(provider["api_key"], REDACTED);
    assert_eq!(
        provider["base_url"],
        "https://api.example.com/[REDACTED_PATH]"
    );
    // ...while the safe identifiers an operator reads a config back by survive.
    assert_eq!(provider["name"], "redaction-provider");
    assert_eq!(provider["provider_type"], "openai");
    assert_eq!(provider["model_patterns"][0], "gpt-*");
    assert_no_canaries(
        &projected,
        &[
            "federation-provider-api-key-canary",
            "federation-base-canary",
        ],
    );
}

/// The same wildcard rule over an object-keyed container, so the two shapes
/// stay one contract rather than two behaviors.
#[test]
fn object_keyed_provider_entries_keep_their_non_credential_fields() {
    let projected = project(
        "ai_stream_router",
        json!({
            "providers": {
                "primary": {
                    "endpoint": "https://router.example.com/v1/stream-endpoint-canary",
                    "weight": 70
                }
            }
        }),
    );
    assert_eq!(
        projected["providers"]["primary"]["endpoint"],
        "https://router.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["providers"]["primary"]["weight"], 70);
    assert_no_canaries(&projected, &["stream-endpoint-canary"]);
}

/// A wildcard entry that is a scalar where the schema expects a container
/// cannot be classified, so it must still fail closed.
#[test]
fn scalar_wildcard_entries_still_fail_closed() {
    let projected = project(
        "ai_federation",
        json!({"providers": ["https://svc:scalar-provider-canary@api.example.com/v1"]}),
    );
    assert_eq!(projected["providers"][0], REDACTED);
    assert_no_canaries(&projected, &["scalar-provider-canary"]);
}

// ---------------------------------------------------------------------------
// Nested sink / parameter maps
// ---------------------------------------------------------------------------

#[test]
fn ai_transcript_audit_sink_endpoint_and_header_values_are_projected() {
    let projected = project(
        "ai_transcript_audit",
        json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/ingest/transcript-path-canary?apikey=transcript-query-canary",
                "custom_headers": {"X-Audit-Token": "transcript-header-canary"},
                "batch_size": 25
            }
        }),
    );
    assert_eq!(
        projected["sink"]["endpoint_url"],
        "https://audit.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(
        projected["sink"]["custom_headers"]["X-Audit-Token"],
        REDACTED
    );
    // Safe-value controls: sink wiring stays legible.
    assert_eq!(projected["sink"]["type"], "http");
    assert_eq!(projected["sink"]["batch_size"], 25);
    assert_no_canaries(
        &projected,
        &[
            "transcript-path-canary",
            "transcript-query-canary",
            "transcript-header-canary",
        ],
    );
}

/// The identity plugins reject a top-level endpoint spelling at admission —
/// `jwks_auth`, `oauth2_introspection`, and `oidc_relying_party` all require a
/// `providers` array and `reject_unknown_fields` the rest. A rule anchored at
/// the config root therefore matches nothing a stored config can ever hold, so
/// the schema must address the nested path that admission actually produces.
#[test]
fn identity_provider_endpoints_are_projected_in_the_admitted_nested_shape() {
    let projected = project(
        "jwks_auth",
        json!({
            "providers": [{
                "issuer": "https://auth.example.com/",
                "jwks_uri": "https://auth.example.com/jwks/jwks-path-canary?tenant=jwks-query-canary",
                "audience": "edge"
            }]
        }),
    );
    let provider = &projected["providers"][0];
    assert_eq!(
        provider["jwks_uri"],
        "https://auth.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    // Safe-value controls: the identifiers an operator reads a provider back by.
    assert_eq!(provider["issuer"], "https://auth.example.com/");
    assert_eq!(provider["audience"], "edge");
    assert_no_canaries(&projected, &["jwks-path-canary", "jwks-query-canary"]);

    let projected = project(
        "oauth2_introspection",
        json!({
            "providers": [{
                "introspection_endpoint": "https://idp.example.com/introspect/oauth-path-canary",
                "issuer": "https://idp.example.com/",
                "client_auth": {"client_id": "edge", "client_secret": "oauth-secret-canary"}
            }]
        }),
    );
    let provider = &projected["providers"][0];
    assert_eq!(
        provider["introspection_endpoint"],
        "https://idp.example.com/[REDACTED_PATH]"
    );
    assert_eq!(provider["client_auth"]["client_secret"], REDACTED);
    assert_eq!(provider["client_auth"]["client_id"], "edge");
    assert_no_canaries(&projected, &["oauth-path-canary", "oauth-secret-canary"]);

    let projected = project(
        "oidc_relying_party",
        json!({
            "providers": [{
                "issuer": "https://idp.example.com/",
                "discovery_url": "https://idp.example.com/.well-known/oidc-discovery-canary",
                "token_endpoint": "https://idp.example.com/token/oidc-token-canary",
                "authorization_endpoint": "https://idp.example.com/authorize/oidc-authz-canary",
                "userinfo_endpoint": "https://idp.example.com/userinfo/oidc-userinfo-canary",
                "end_session_endpoint": "https://idp.example.com/logout/oidc-logout-canary",
                "jwks_uri": "https://idp.example.com/jwks/oidc-jwks-canary",
                "client_id": "edge"
            }],
            "session": {"ttl_secs": 3600}
        }),
    );
    let provider = &projected["providers"][0];
    for field in [
        "discovery_url",
        "userinfo_endpoint",
        "end_session_endpoint",
        "jwks_uri",
    ] {
        assert_eq!(
            provider[field], "https://idp.example.com/[REDACTED_PATH]",
            "provider field {field} was not projected"
        );
    }
    // The additive name-heuristic floor is deliberately stricter for these
    // spellings: `token` is classified per segment, while `authorization`
    // matches the built-in sensitive substring list. Schema projection must
    // never weaken that existing full redaction.
    assert_eq!(provider["token_endpoint"], REDACTED);
    assert_eq!(provider["authorization_endpoint"], REDACTED);
    assert_eq!(provider["client_id"], "edge");
    assert_eq!(projected["session"]["ttl_secs"], 3600);
    assert_no_canaries(
        &projected,
        &[
            "oidc-discovery-canary",
            "oidc-token-canary",
            "oidc-authz-canary",
            "oidc-userinfo-canary",
            "oidc-logout-canary",
            "oidc-jwks-canary",
        ],
    );
}

/// `mcp_gateway` carries its upstream URLs under `servers.<id>.upstream_url`;
/// there is no top-level spelling. Construction refuses userinfo, query, and
/// fragment, but a hosted MCP server's ingest token still rides the path — and
/// a config stored `enabled: false` skips construction entirely.
#[test]
fn mcp_gateway_per_server_upstream_urls_are_projected() {
    let projected = project(
        "mcp_gateway",
        json!({
            "servers": {
                "github": {
                    "upstream_url": "https://mcp.example.com/v1/mcp-token-canary/sse",
                    "namespace": "gh",
                    "enabled": true
                }
            },
            "endpoint": {"path": "/mcp"}
        }),
    );
    let server = &projected["servers"]["github"];
    assert_eq!(
        server["upstream_url"],
        "https://mcp.example.com/[REDACTED_PATH]"
    );
    // Safe-value controls: routing metadata an operator needs stays readable.
    assert_eq!(server["namespace"], "gh");
    assert_eq!(server["enabled"], true);
    assert_eq!(projected["endpoint"]["path"], "/mcp");
    assert_no_canaries(&projected, &["mcp-token-canary"]);
}

#[test]
fn chargeback_clickhouse_endpoint_and_insert_params_are_projected() {
    let projected = project(
        "api_chargeback_sink",
        json!({
            "clickhouse": {
                "url": "https://clickhouse.example.com:8443/chargeback-path-canary",
                "database": "ferrum",
                "table": "charges_raw",
                "insert_query_params": {"async_insert": "chargeback-param-canary"}
            }
        }),
    );
    assert_eq!(
        projected["clickhouse"]["url"],
        "https://clickhouse.example.com:8443/[REDACTED_PATH]"
    );
    assert_eq!(
        projected["clickhouse"]["insert_query_params"]["async_insert"],
        REDACTED
    );
    // Safe-value controls: routing metadata an operator needs stays readable.
    assert_eq!(projected["clickhouse"]["database"], "ferrum");
    assert_eq!(projected["clickhouse"]["table"], "charges_raw");
    assert_no_canaries(
        &projected,
        &["chargeback-path-canary", "chargeback-param-canary"],
    );
}

// ---------------------------------------------------------------------------
// Placeholder write-back detection (issue #5925)
// ---------------------------------------------------------------------------

/// The sites where `config` already carries a redaction placeholder, as the
/// admin write path finds them.
fn placeholder_sites(plugin: &str, config: &Value) -> Vec<String> {
    let recorder = PlaceholderSiteRecorder::default();
    let mut walked = config.clone();
    project_plugin_config_with(plugin, &mut walked, "/config", &recorder);
    recorder.into_sites()
}

#[test]
fn redaction_placeholder_matches_only_the_exact_markers() {
    for marker in [
        json!("[REDACTED]"),
        json!("https://collector.example.com/[REDACTED_PATH]"),
        json!("https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"),
        json!("https://collector.example.com?[REDACTED_QUERY]"),
        json!("https://collector.example.com#[REDACTED_FRAGMENT]"),
        json!("https://redacted@collector.example.com"),
        // A partial edit that keeps one marker still carries it.
        json!("https://other.example.com:8443/[REDACTED_PATH]?page=2"),
        json!("redis://redacted@cache.internal:6379/3?[REDACTED_QUERY]"),
        json!("postgres://redacted@db.internal/app"),
    ] {
        assert!(is_redaction_placeholder(&marker), "{marker} not matched");
    }

    for legitimate in [
        json!("[redacted]"),
        json!("[REDACTED] "),
        json!(" [REDACTED]"),
        json!("x[REDACTED]"),
        json!("REDACTED"),
        json!("redacted"),
        json!("https://collector.example.com"),
        json!("https://collector.example.com/v1/[REDACTED_PATH]"),
        json!("https://collector.example.com/[REDACTED_PATH]x"),
        json!("https://collector.example.com?q=[REDACTED_QUERY]"),
        json!("https://redacted:password@collector.example.com/"),
        json!("https://user@collector.example.com/"),
        json!("redis://cache.internal:6379/3"),
        json!(42),
        json!(true),
        Value::Null,
        json!(["[REDACTED]"]),
        json!({"key": "[REDACTED]"}),
    ] {
        assert!(
            !is_redaction_placeholder(&legitimate),
            "{legitimate} wrongly matched"
        );
    }
}

/// Every value an operator read masks is found again when that read is sent
/// back, and the stored (raw) config itself trips nothing.
#[test]
fn placeholder_sites_are_exactly_the_masked_sites_of_a_round_tripped_read() {
    let raw = json!({
        "endpoint_url": "https://collector.example.com/push/path-canary?api_key=query-canary",
        "custom_headers": {"x-honeycomb-team": "vendor-canary"},
        "api_key": "name-heuristic-canary",
        "fallback": "https://user:pass@backup.example.com/ingest",
        "batch_size": 50,
        "service": "orders"
    });
    assert!(
        placeholder_sites("http_logging", &raw).is_empty(),
        "the stored config carries no placeholder"
    );

    let projected = project("http_logging", raw);
    let mut sites = placeholder_sites("http_logging", &projected);
    sites.sort();
    assert_eq!(
        sites,
        vec![
            "/config/api_key".to_string(),
            "/config/custom_headers/x-honeycomb-team".to_string(),
            "/config/endpoint_url".to_string(),
            "/config/fallback".to_string(),
        ]
    );
}

/// A layered site (structural URL projection, then the name heuristic) is
/// judged on the value the caller sent, not on the earlier layer's output.
#[test]
fn placeholder_sites_ignore_a_later_layer_rendering_an_earlier_layers_output() {
    let raw = json!({
        "providers": [{
            "issuer": "https://idp.example.com/",
            "token_endpoint": "https://idp.example.com/oauth/token",
            "client_id": "edge"
        }]
    });
    assert!(placeholder_sites("oidc_relying_party", &raw).is_empty());

    let projected = project("oidc_relying_party", raw);
    assert_eq!(projected["providers"][0]["token_endpoint"], REDACTED);
    assert_eq!(
        placeholder_sites("oidc_relying_party", &projected),
        vec!["/config/providers/0/token_endpoint".to_string()]
    );
}

/// A placeholder only matters where the projection masks: the same string in a
/// field the read shows verbatim was put there by the caller, not the read.
#[test]
fn placeholder_outside_a_masked_site_is_not_reported() {
    let config = json!({"service": "[REDACTED]", "batch_size": 50});
    assert!(placeholder_sites("http_logging", &config).is_empty());
}
