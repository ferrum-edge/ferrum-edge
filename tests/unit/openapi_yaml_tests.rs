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
