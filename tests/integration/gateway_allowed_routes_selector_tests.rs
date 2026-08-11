//! Security regressions for Gateway API `allowedRoutes.namespaces.selector`.
//!
//! These tests exercise the public parser seam plus translation, attachment,
//! status, and successive full-snapshot reconciliation behavior.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslateError, K8sTranslation, K8sTranslationOptions,
    translate_k8s_objects, validate_gateway_listener_allowed_routes,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, plan_gateway_api_status_updates,
};
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new())
}

fn object(kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "Namespace" {
            "v1".to_string()
        } else {
            "gateway.networking.k8s.io/v1".to_string()
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn namespace(name: &str, labels: &[(&str, &str)]) -> K8sObject {
    let mut object = object("Namespace", name, "", json!({}));
    object.metadata.labels = labels
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();
    object
}

fn listener(selector: Value) -> Value {
    json!({
        "name": "cross-namespace",
        "port": 80,
        "protocol": "HTTP",
        "allowedRoutes": {
            "namespaces": {
                "from": "Selector",
                "selector": selector
            }
        }
    })
}

fn gateway(selector: Value) -> K8sObject {
    object(
        "Gateway",
        "edge",
        "platform",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [listener(selector)]
        }),
    )
}

fn route() -> K8sObject {
    object(
        "HTTPRoute",
        "payments",
        "tenant",
        json!({
            "parentRefs": [{
                "name": "edge",
                "namespace": "platform",
                "sectionName": "cross-namespace"
            }],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": "/payments"}}],
                "backendRefs": [{"name": "payments", "port": 8080}]
            }]
        }),
    )
}

fn objects(selector: Value) -> Vec<K8sObject> {
    vec![
        namespace(
            "tenant",
            &[("team", "payments"), ("env", "prod"), ("track", "stable")],
        ),
        namespace("platform", &[("team", "platform")]),
        gateway(selector),
        route(),
    ]
}

fn valid_selector() -> Value {
    json!({
        "matchLabels": {
            "team": "payments",
            "security.example.com/tier": "pci"
        },
        "matchExpressions": [
            {"key": "env", "operator": "In", "values": ["prod"]},
            {"key": "track", "operator": "NotIn", "values": ["canary"]},
            {"key": "team", "operator": "Exists"},
            {"key": "blocked", "operator": "DoesNotExist"}
        ]
    })
}

fn translate_skipping_rejected_resources(objects: &[K8sObject]) -> K8sTranslation {
    let mut retained = objects.to_vec();
    loop {
        match translate_k8s_objects(&retained, options()) {
            Ok(translation) => return translation,
            Err(error) => {
                let (kind, namespace, name) = error_identity(&error);
                let prior_len = retained.len();
                retained.retain(|object| {
                    object.kind != kind
                        || object.metadata.namespace != namespace
                        || object.metadata.name != name
                });
                assert!(
                    retained.len() < prior_len,
                    "rejected resource must be removable from the reconciliation snapshot"
                );
            }
        }
    }
}

fn error_identity(error: &K8sTranslateError) -> (&str, &str, &str) {
    match error {
        K8sTranslateError::Unsupported(resource) => {
            (&resource.kind, &resource.namespace, &resource.name)
        }
        K8sTranslateError::InvalidResource {
            kind,
            namespace,
            name,
            ..
        } => (kind, namespace, name),
    }
}

fn listener_condition<'a>(status: &'a Value, condition_type: &str) -> &'a Value {
    status["listeners"][0]["conditions"]
        .as_array()
        .expect("listener conditions")
        .iter()
        .find(|condition| condition["type"].as_str() == Some(condition_type))
        .expect("listener condition")
}

#[test]
fn parser_accepts_all_valid_namespace_modes_and_selector_operators() {
    for listener in [
        json!({"allowedRoutes": {"namespaces": {"from": "All"}}}),
        json!({"allowedRoutes": {"namespaces": {"from": "Same"}}}),
        listener(json!({})),
        listener(valid_selector()),
    ] {
        validate_gateway_listener_allowed_routes(&listener)
            .expect("valid allowedRoutes namespace policy");
    }

    let mut selected_objects = objects(valid_selector());
    selected_objects[0]
        .metadata
        .labels
        .insert("security.example.com/tier".to_string(), "pci".to_string());
    let translation =
        translate_k8s_objects(&selected_objects, options()).expect("valid selector translates");
    assert_eq!(translation.config.proxies.len(), 1);
}

#[test]
fn parser_rejects_every_malformed_selector_shape_and_operator_cardinality_atomically() {
    let secret = "DO-NOT-ECHO-SELECTOR-VALUE";
    let invalid_selectors = vec![
        json!({"matchLables": {"team": "payments"}}),
        json!({"matchLabels": {"team": "payments"}, "extra": true}),
        json!({"matchExpressions": [{"key": "team", "operator": "Exists", "extra": true}]}),
        json!({"matchExpressions": [{"key": "team", "operater": "Exists"}]}),
        json!({"matchLabels": []}),
        json!({"matchLabels": {"team": 7}}),
        json!({"matchLabels": {"/bad": "payments"}}),
        json!({"matchLabels": {"team": "-bad"}}),
        json!({"matchExpressions": {}}),
        json!({"matchExpressions": ["not-an-object"]}),
        json!({"matchExpressions": [{"operator": "Exists"}]}),
        json!({"matchExpressions": [{"key": 7, "operator": "Exists"}]}),
        json!({"matchExpressions": [{"key": "/bad", "operator": "Exists"}]}),
        json!({"matchExpressions": [{"key": "team"}]}),
        json!({"matchExpressions": [{"key": "team", "operator": 7}]}),
        json!({"matchExpressions": [{"key": "team", "operator": secret}]}),
        json!({"matchExpressions": [{"key": "team", "operator": "In"}]}),
        json!({"matchExpressions": [{"key": "team", "operator": "In", "values": []}]}),
        json!({"matchExpressions": [{"key": "team", "operator": "NotIn"}]}),
        json!({"matchExpressions": [{"key": "team", "operator": "NotIn", "values": []}]}),
        json!({
            "matchExpressions": [
                {"key": "team", "operator": "Exists", "values": ["payments"]}
            ]
        }),
        json!({
            "matchExpressions": [
                {"key": "team", "operator": "DoesNotExist", "values": ["payments"]}
            ]
        }),
        json!({"matchExpressions": [{"key": "team", "operator": "In", "values": secret}]}),
        json!({"matchExpressions": [{"key": "team", "operator": "In", "values": [7]}]}),
        json!({"matchExpressions": [{"key": "team", "operator": "In", "values": ["-bad"]}]}),
        json!({
            "matchExpressions": [
                {"key": "team", "operator": "In", "values": ["payments"]},
                {"key": "security", "operator": secret, "values": ["pci"]}
            ]
        }),
    ];

    for selector in invalid_selectors {
        let error = validate_gateway_listener_allowed_routes(&listener(selector))
            .expect_err("malformed selector must reject the whole listener");
        let message = error.to_string();
        assert!(message.starts_with("spec.listeners[].allowedRoutes.namespaces.selector"));
        assert!(
            !message.contains(secret),
            "selector values must stay redacted"
        );
    }

    for malformed_listener in [
        json!({"allowedRoutes": []}),
        json!({"allowedRoutes": {"namespaces": []}}),
        json!({"allowedRoutes": {"namespaces": {"from": 7}}}),
        json!({"allowedRoutes": {"namespaces": {"from": "Unknown"}}}),
        json!({"allowedRoutes": {"namespaces": {"from": "Selector"}}}),
        json!({"allowedRoutes": {"namespaces": {"from": "Selector", "selector": []}}}),
    ] {
        validate_gateway_listener_allowed_routes(&malformed_listener)
            .expect_err("malformed allowedRoutes namespace shape must reject");
    }
}

#[test]
fn malformed_mixed_selector_does_not_broaden_cross_namespace_attachment() {
    let invalid_gateway = gateway(json!({
        "matchLabels": {
            "team": "payments",
            "required-security-boundary": 7
        }
    }));
    let objects = vec![
        namespace("tenant", &[("team", "payments")]),
        namespace("platform", &[("team", "platform")]),
        invalid_gateway,
        route(),
    ];

    let translation = translate_skipping_rejected_resources(&objects);
    assert!(
        translation.config.proxies.is_empty(),
        "dropping the malformed label would incorrectly authorize tenant"
    );
    assert!(
        translation
            .config
            .mesh
            .as_ref()
            .is_none_or(|mesh| mesh.services.is_empty()),
        "an invalid listener must not be materialized"
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let gateway_status = &updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("Gateway status update")
        .status;
    assert_eq!(gateway_status["listeners"][0]["attachedRoutes"], 0);
    let accepted = listener_condition(gateway_status, "Accepted");
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], "Invalid");
    assert_eq!(
        accepted["message"],
        "spec.listeners[].allowedRoutes.namespaces.selector.matchLabels value: must be a string"
    );
    for condition_type in ["ResolvedRefs", "Programmed"] {
        let condition = listener_condition(gateway_status, condition_type);
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "Invalid");
        assert_eq!(condition["message"], accepted["message"]);
    }
    assert!(
        !accepted["message"]
            .as_str()
            .expect("status message")
            .contains("required-security-boundary")
    );
}

#[test]
fn unknown_selector_field_does_not_broaden_cross_namespace_attachment() {
    let secret = "DO-NOT-ECHO-SELECTOR-VALUE";
    let invalid_gateway = gateway(json!({
        "matchLables": {"team": secret}
    }));
    let objects = vec![
        namespace("tenant", &[("team", "payments")]),
        namespace("platform", &[("team", "platform")]),
        invalid_gateway,
        route(),
    ];

    let translation = translate_skipping_rejected_resources(&objects);
    assert!(
        translation.config.proxies.is_empty(),
        "typoed selector fields must not authorize tenant"
    );
    assert!(
        translation
            .config
            .mesh
            .as_ref()
            .is_none_or(|mesh| mesh.services.is_empty()),
        "an invalid listener must not be materialized"
    );

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let gateway_status = &updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("Gateway status update")
        .status;
    assert_eq!(gateway_status["listeners"][0]["attachedRoutes"], 0);
    let accepted = listener_condition(gateway_status, "Accepted");
    assert_eq!(accepted["status"], "False");
    assert_eq!(accepted["reason"], "Invalid");
    assert_eq!(
        accepted["message"],
        "spec.listeners[].allowedRoutes.namespaces.selector: may contain only matchLabels and matchExpressions"
    );
    for condition_type in ["ResolvedRefs", "Programmed"] {
        let condition = listener_condition(gateway_status, condition_type);
        assert_eq!(condition["status"], "False");
        assert_eq!(condition["reason"], "Invalid");
        assert_eq!(condition["message"], accepted["message"]);
    }
    let message = accepted["message"].as_str().expect("status message");
    for leaked in ["matchLables", secret, "team", "payments"] {
        assert!(
            !message.contains(leaked),
            "selector diagnostics must stay redacted: leaked {leaked}"
        );
    }
}

#[test]
fn valid_to_invalid_reload_withdraws_then_recovery_and_deletion_reconcile() {
    let mut valid = objects(json!({
        "matchLabels": {"team": "payments"}
    }));
    let initial = translate_skipping_rejected_resources(&valid);
    assert_eq!(initial.config.proxies.len(), 1);

    valid[2].spec["listeners"][0]["allowedRoutes"]["namespaces"]["selector"] = json!({
        "matchExpressions": [
            {"key": "team", "operator": "In", "values": ["payments"]},
            {"key": "security", "operator": "In", "values": []}
        ]
    });
    let invalid_reload = translate_skipping_rejected_resources(&valid);
    assert!(
        invalid_reload.config.proxies.is_empty(),
        "invalid update must withdraw prior cross-namespace authorization"
    );

    valid[2].spec["listeners"][0]["allowedRoutes"]["namespaces"]["selector"] =
        json!({"matchLabels": {"team": "payments"}});
    let recovered = translate_skipping_rejected_resources(&valid);
    assert_eq!(
        recovered.config.proxies.len(),
        1,
        "fixing the selector must restore attachment"
    );

    let after_route_deletion = translate_skipping_rejected_resources(&valid[..3]);
    assert!(
        after_route_deletion.config.proxies.is_empty(),
        "route deletion must remove materialized attachment"
    );

    let after_gateway_deletion =
        translate_skipping_rejected_resources(&[valid[0].clone(), valid[1].clone()]);
    assert!(
        after_gateway_deletion
            .config
            .mesh
            .as_ref()
            .is_none_or(|mesh| mesh.services.is_empty()),
        "Gateway deletion must remove listener materialization"
    );
}

#[test]
fn invalid_listener_does_not_block_valid_sibling_listener() {
    let gateway = object(
        "Gateway",
        "edge",
        "platform",
        json!({
            "gatewayClassName": "ferrum",
            "listeners": [
                listener(json!({"matchLabels": {"team": 7}})),
                {
                    "name": "public",
                    "port": 8080,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }
            ]
        }),
    );
    let mut route = route();
    route.spec["parentRefs"][0]["sectionName"] = json!("public");
    let objects = vec![
        namespace("tenant", &[("team", "payments")]),
        namespace("platform", &[]),
        gateway,
        route,
    ];

    let translation =
        translate_k8s_objects(&objects, options()).expect("valid sibling listener translates");
    assert_eq!(translation.config.proxies.len(), 1);
    let service_names: Vec<&str> = translation
        .config
        .mesh
        .as_ref()
        .expect("valid listener service")
        .services
        .iter()
        .map(|service| service.name.as_str())
        .collect();
    assert_eq!(service_names, vec!["gateway-4-edge-public"]);

    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let status = &updates
        .iter()
        .find(|update| update.kind == "Gateway")
        .expect("Gateway status")
        .status;
    assert_eq!(listener_condition(status, "Accepted")["status"], "False");
    assert_eq!(
        status["listeners"][1]["conditions"][0]["status"],
        Value::String("True".to_string())
    );
    assert_eq!(status["listeners"][1]["attachedRoutes"], Value::from(1_u64));
}

#[test]
fn status_is_owned_by_ferrum_controller_for_selector_rejections() {
    let objects = objects(json!({"matchLabels": {"team": 7}}));
    let updates = plan_gateway_api_status_updates(&objects, options(), &[]);
    let route_status = updates
        .iter()
        .find(|update| update.kind == "HTTPRoute")
        .expect("route status");
    assert_eq!(
        route_status.status["parents"][0]["controllerName"],
        FERRUM_GATEWAY_CONTROLLER_NAME
    );
    assert_eq!(
        route_status.status["parents"][0]["conditions"][0]["status"],
        "False"
    );
    assert_eq!(
        route_status.status["parents"][0]["conditions"][0]["reason"],
        "NotAllowedByListeners"
    );
}
