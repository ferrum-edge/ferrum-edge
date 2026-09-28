//! Gateway API `RequestHeaderModifier` may not write the gateway-owned
//! `x-consumer-*` request-header namespace.
//!
//! `mesh_route_dispatch` refuses a `request_transform` destination under the
//! namespace when it is constructed, and it is a fail-closed plugin. If the
//! translator admitted the filter, the emitted plugin config would fail the
//! whole plugin-cache build: every later config change in the cluster would be
//! rejected, and a restarting data plane could not start. The translator must
//! therefore refuse only the offending route, report it in that route's
//! status, and keep translating the rest of the snapshot.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslateError, K8sTranslationOptions, translate_k8s_objects,
    translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

/// Marker the status writer maps to `Accepted=False` / `UnsupportedValue`.
const UNSUPPORTED_SHAPE_MARKER: &str = "is not implemented by Ferrum";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, api_version: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    object(
        "GatewayClass",
        "gateway.networking.k8s.io/v1",
        "",
        "ferrum",
        json!({"controllerName": FERRUM_GATEWAY_CONTROLLER_NAME}),
    )
}

fn gateway() -> K8sObject {
    object(
        "Gateway",
        "gateway.networking.k8s.io/v1",
        "default",
        "edge",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
        }),
    )
}

fn service() -> K8sObject {
    object(
        "Service",
        "v1",
        "default",
        "api",
        json!({"ports": [{"name": "http", "port": 8080, "targetPort": 8080}]}),
    )
}

/// An HTTPRoute on `edge` whose one rule carries `filter`.
fn http_route(name: &str, filter: Value) -> K8sObject {
    object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        "default",
        name,
        json!({
            "hostnames": [format!("{name}.example.com")],
            "parentRefs": [{"name": "edge"}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": format!("/{name}")}}],
                "backendRefs": [{"name": "api", "port": 8080}],
                "filters": [filter]
            }]
        }),
    )
}

fn request_header_modifier(field: &str, header: &str) -> Value {
    json!({
        "type": "RequestHeaderModifier",
        "requestHeaderModifier": {field: [{"name": header, "value": "admin"}]}
    })
}

fn snapshot(routes: Vec<K8sObject>) -> Vec<K8sObject> {
    let mut objects = vec![gateway_class(), gateway(), service()];
    objects.extend(routes);
    objects
}

fn route_condition_field(
    updates: &[GatewayApiStatusUpdate],
    name: &str,
    condition: &str,
    field: &str,
) -> Option<String> {
    let update = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute" && update.name == name)?;
    update
        .status
        .get("parents")?
        .as_array()?
        .iter()
        .filter_map(|parent| parent.get("conditions")?.as_array())
        .flatten()
        .find(|entry| entry.get("type").and_then(Value::as_str) == Some(condition))
        .and_then(|entry| entry.get(field).and_then(Value::as_str))
        .map(ToOwned::to_owned)
}

#[test]
fn consumer_namespace_request_header_modifier_refuses_only_its_own_route() {
    let objects = snapshot(vec![
        http_route("spoof", request_header_modifier("set", "x-consumer-role")),
        http_route("tenant", request_header_modifier("set", "x-tenant")),
    ]);

    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, options()).expect("translate snapshot");

    // Exactly the offending HTTPRoute is refused, and the error names it.
    assert_eq!(skipped.len(), 1, "{skipped:?}");
    let (key, error) = skipped.iter().next().expect("one skipped route");
    assert_eq!(
        (key.kind.as_str(), key.name.as_str()),
        ("HTTPRoute", "spoof")
    );
    assert!(
        matches!(error, K8sTranslateError::InvalidResource { .. }),
        "expected a per-resource refusal: {error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("\"spoof\" \"HTTPRoute\"")
            && message.contains("requestHeaderModifier.set[0].name")
            && message.contains("`x-consumer-*`")
            && message.contains(UNSUPPORTED_SHAPE_MARKER),
        "{message}"
    );

    // The valid sibling still translates, and every emitted plugin config
    // constructs, so the plugin-cache build cannot fail on this snapshot.
    let plugins = &translation.config.plugin_configs;
    for plugin in plugins {
        ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
            .unwrap_or_else(|error| panic!("{}: {error}", plugin.plugin_name));
    }
    let rendered: Vec<String> = plugins
        .iter()
        .map(|plugin| plugin.config.to_string().to_ascii_lowercase())
        .collect();
    assert!(
        rendered.iter().any(|config| config.contains("x-tenant")),
        "the valid route's header modifier must still be emitted: {plugins:?}"
    );
    assert!(
        rendered.iter().all(|config| !config.contains("x-consumer-role")),
        "no emitted plugin may carry the refused destination: {plugins:?}"
    );

    // Status names the refused route; the sibling stays accepted.
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    assert_eq!(
        route_condition_field(&updates, "spoof", "Accepted", "status").as_deref(),
        Some("False")
    );
    assert_eq!(
        route_condition_field(&updates, "spoof", "Accepted", "reason").as_deref(),
        Some("UnsupportedValue")
    );
    assert_eq!(
        route_condition_field(&updates, "tenant", "Accepted", "status").as_deref(),
        Some("True")
    );
}

#[test]
fn consumer_namespace_refusal_covers_set_add_case_and_underscore_spellings() {
    for (field, header) in [
        ("set", "x-consumer-role"),
        ("set", "X-Consumer-Role"),
        ("add", "x-consumer-groups"),
        ("set", "x-consumer-username"),
        ("add", "x-consumer-custom-id"),
        ("set", "X_Consumer_Role"),
        ("add", "x_consumer-groups"),
        ("set", "x-consumer_tenant"),
    ] {
        let route = http_route("spoof", request_header_modifier(field, header));
        let objects = snapshot(vec![route]);
        let error = translate_k8s_objects(&objects, options())
            .expect_err("a consumer-namespace request header modifier must be refused");
        let message = error.to_string();
        assert!(
            message.contains(&format!("requestHeaderModifier.{field}[0].name"))
                && message.contains("`x-consumer-*`"),
            "{field} {header}: {message}"
        );
    }
}

#[test]
fn consumer_namespace_remove_and_response_side_modifiers_stay_admitted() {
    // Removing a client value is always safe, and the namespace is a
    // request-header namespace: a response header of the same name is not a
    // gateway assertion to a backend.
    let remove = json!({
        "type": "RequestHeaderModifier",
        "requestHeaderModifier": {"remove": ["X-Consumer-Role", "x_consumer_groups"]}
    });
    let response = json!({
        "type": "ResponseHeaderModifier",
        "responseHeaderModifier": {"set": [{"name": "x-consumer-role", "value": "echo"}]}
    });
    for (label, filter) in [("remove", remove), ("response", response)] {
        let objects = snapshot(vec![http_route("allowed", filter)]);
        let translation = translate_k8s_objects(&objects, options())
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        for plugin in &translation.config.plugin_configs {
            ferrum_edge::plugins::validate_plugin_config(&plugin.plugin_name, &plugin.config)
                .unwrap_or_else(|error| panic!("{label} {}: {error}", plugin.plugin_name));
        }
    }
}
