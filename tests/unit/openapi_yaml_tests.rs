use serde_json::json;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};

fn get_path<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for key in path {
        current = current
            .get(Value::String((*key).to_string()))
            .unwrap_or_else(|| panic!("missing OpenAPI path component: {key}"));
    }
    current
}

#[test]
fn waf_scoring_weights_reject_unknown_severities() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let weights = get_path(
        &spec,
        &[
            "components",
            "schemas",
            "WafPluginConfig",
            "properties",
            "scoring",
            "properties",
            "weights",
        ],
    );

    assert_eq!(
        weights
            .get(Value::String("additionalProperties".to_string()))
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn access_control_schema_matches_runtime_validation() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AccessControlConfig")
        .expect("missing AccessControlConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AccessControlConfig schema compiles");

    for config in [
        json!({"allowed_consumers": ["alice"]}),
        json!({"disallowed_consumers": ["bad"], "allow_authenticated_identity": true}),
        json!({"allow_authenticated_identity": true}),
        json!({"allow_authenticated_identity": true, "allowed_consumers": []}),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({}),
        json!({"allowed_consumer": ["alice"]}),
        json!({"allowed_consumers": [], "allowed_groups": []}),
        json!({"allowed_consumers": ["alice"], "allow_authenticated_identity": true}),
        json!({"allowed_groups": ["engineering"], "allow_authenticated_identity": true}),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

#[test]
fn ai_tool_governor_schema_matches_runtime_invariants() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/AiToolGovernorConfig"
    });
    schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("AiToolGovernorConfig schema compiles");

    for config in [
        json!({
            "enabled": false,
            "mode": "ignored-invalid-mode",
            "default_action": "ignored-invalid-action",
            "tools": {"": {"action": "ignored-invalid-action"}},
            "inspect": "ignored-invalid-inspection",
            "approval": "ignored-invalid-approval"
        }),
        json!({"default_action": "deny", "tools": {}}),
        json!({"tools": {"search": {"action": "allow"}}}),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "required_args": ["query"],
                    "blocked_arg_patterns": [{"name": "secret", "regex": "secret"}]
                }
            }
        }),
        json!({
            "default_action": "allow",
            "tools": {"deploy": {"action": "require_approval"}},
            "inspect": {"request_tool_definitions": true, "response_tool_calls": false}
        }),
        json!({
            "mode": "dry_run",
            "tools": {"deploy": {"action": "require_approval"}}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "https://approval.example/decide"}
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({
            "tools": {"search": {"action": "allow"}},
            "inspect": {
                "request_tool_definitions": false,
                "response_tool_calls": false,
                "streaming_response_tool_calls": false,
                "mcp_tool_calls": false,
                "a2a_methods": false
            }
        }),
        json!({"default_action": "allow"}),
        json!({"default_action": "allow", "tools": {}}),
        json!({"tools": {"": {"action": "deny"}}}),
        json!({"tools": {"search": {"action": "redact_args"}}}),
        json!({
            "tools": {"search": {"action": "redact_args", "blocked_arg_patterns": []}}
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "", "regex": "secret"}]
                }
            }
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "secret", "regex": ""}]
                }
            }
        }),
        json!({"tools": {"deploy": {"action": "require_approval"}}}),
        json!({"default_action": "require_approval", "tools": {}}),
        json!({"tools": {"search": {"action": "allow", "required_args": [""]}}}),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": ""}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "ftp://approval.example/decide"}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "https:///decide"}
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

fn plugin_config_schema_mapping(spec: &serde_json::Value) -> BTreeMap<String, String> {
    let all_of = spec
        .pointer("/components/schemas/PluginConfig/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("PluginConfig allOf should be an array");

    let mut mapping = BTreeMap::new();
    for entry in all_of {
        let plugin_name = entry
            .pointer("/if/properties/plugin_name/const")
            .and_then(serde_json::Value::as_str)
            .expect("PluginConfig conditional should name a plugin");
        let schema_ref = entry
            .pointer("/then/properties/config/$ref")
            .and_then(serde_json::Value::as_str)
            .expect("PluginConfig conditional should constrain config");

        assert!(
            mapping
                .insert(plugin_name.to_string(), schema_ref.to_string())
                .is_none(),
            "duplicate PluginConfig schema conditional for {plugin_name}"
        );
    }

    mapping
}

#[test]
fn plugin_config_schema_maps_every_builtin_plugin() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let custom_plugins: BTreeSet<_> = ferrum_edge::custom_plugins::custom_plugin_names()
        .into_iter()
        .collect();
    let builtins: BTreeSet<_> = ferrum_edge::plugins::available_plugins()
        .into_iter()
        .filter(|name| !custom_plugins.contains(name))
        .collect();

    let mapping = plugin_config_schema_mapping(&spec);
    let documented: BTreeSet<_> = mapping.keys().map(String::as_str).collect();

    assert_eq!(
        documented, builtins,
        "PluginConfig schema conditionals should cover every built-in plugin"
    );
    assert!(
        !mapping.contains_key("semantic_ai_firewall"),
        "undocumented ai_semantic_firewall alias must not re-enter OpenAPI"
    );

    for (plugin_name, schema_ref) in mapping {
        let schema_name = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        let pointer = format!("/components/schemas/{schema_name}");
        assert!(
            spec.pointer(&pointer).is_some(),
            "PluginConfig ref for {plugin_name} points to missing schema {schema_name}"
        );
    }
}

#[test]
fn plugin_config_schema_applies_plugin_specific_config() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/PluginConfig"
    });
    schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());

    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("PluginConfig schema compiles");
    let plugin_config =
        |plugin_name: &str, config: Option<serde_json::Value>| -> serde_json::Value {
            let mut value = json!({
                "plugin_name": plugin_name,
                "scope": "global",
                "enabled": true
            });
            if let Some(config) = config {
                value
                    .as_object_mut()
                    .expect("plugin config should be object")
                    .insert("config".to_string(), config);
            }
            value
        };

    let valid = json!({
        "plugin_name": "ws_message_size_limiting",
        "scope": "global",
        "enabled": true,
        "config": {"max_frame_bytes": 1024}
    });
    assert!(validator.validate(&valid).is_ok(), "config should be valid");

    let invalid = json!({
        "plugin_name": "ws_message_size_limiting",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert!(
        validator.validate(&invalid).is_err(),
        "ws_message_size_limiting should require max_frame_bytes through PluginConfig"
    );

    for (plugin_name, config) in [
        ("udp_rate_limiting", json!({"datagrams_per_second": 100})),
        (
            "fault_injection",
            json!({"abort": {"status_code": 503, "percentage": 5.0}}),
        ),
        ("ai_rate_limiter", json!({"token_limit": 100000})),
        ("ai_request_guard", json!({"max_tokens_limit": 2048})),
        ("ai_response_guard", json!({"require_json": true})),
        ("ai_semantic_firewall", json!({"enabled": false})),
        (
            "ai_semantic_firewall",
            json!({
                "provider": {
                    "type": "openai_compatible_embeddings",
                    "endpoint": "https://embeddings.example/v1"
                }
            }),
        ),
    ] {
        let value = plugin_config(plugin_name, Some(config));
        assert!(
            validator.validate(&value).is_ok(),
            "{plugin_name} config should be valid: {value}"
        );
    }

    for (plugin_name, config) in [
        ("udp_rate_limiting", None),
        ("udp_rate_limiting", Some(json!({}))),
        ("fault_injection", None),
        ("fault_injection", Some(json!({}))),
        ("ai_rate_limiter", None),
        ("ai_rate_limiter", Some(json!({}))),
        ("ai_rate_limiter", Some(json!({"token_limit": 0}))),
        ("ai_request_guard", None),
        ("ai_request_guard", Some(json!({}))),
        ("ai_request_guard", Some(json!({"allowed_models": []}))),
        (
            "ai_request_guard",
            Some(json!({"require_user_field": false})),
        ),
        ("ai_response_guard", None),
        ("ai_response_guard", Some(json!({}))),
        ("ai_response_guard", Some(json!({"require_json": false}))),
        ("ai_response_guard", Some(json!({"blocked_phrases": []}))),
        ("ai_semantic_firewall", None),
        ("ai_semantic_firewall", Some(json!({}))),
    ] {
        let value = plugin_config(plugin_name, config);
        assert!(
            validator.validate(&value).is_err(),
            "{plugin_name} config should be invalid: {value}"
        );
    }

    let custom = json!({
        "plugin_name": "custom_observer",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert!(
        validator.validate(&custom).is_ok(),
        "custom plugins should keep generic PluginConfig config shape"
    );
}
