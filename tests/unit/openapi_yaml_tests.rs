use serde_json::json;
use serde_yaml::Value;

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
