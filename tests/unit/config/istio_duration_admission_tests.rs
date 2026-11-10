//! Istio duration fields that used to be dropped silently on a parse failure
//! (issue #7257).
//!
//! * `DestinationRule.trafficPolicy.connectionPool.tcp.connectTimeout` that
//!   did not parse became "unset" (the default connect timeout applied) while
//!   every sibling duration refused the resource; `0s` and values above the
//!   24 h ceiling reached `backend_connect_timeout_ms`, which config
//!   validation bounds to `1..=MAX_TIMEOUT_MS`.
//! * `VirtualService.http[].timeout` that did not parse became "no timeout",
//!   which disabled the route timeout.
//!
//! Both now refuse the resource (`FerrumAccepted=False`).

use std::collections::HashMap;

use ferrum_edge::config::types::MAX_TIMEOUT_MS;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: "sample".to_string(),
            uid: "uid-sample".to_string(),
            namespace: "default".to_string(),
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

fn destination_rule(connect_timeout: Value) -> K8sObject {
    object(
        "DestinationRule",
        json!({
            "host": "api.default.svc.cluster.local",
            "trafficPolicy": {"connectionPool": {"tcp": {"connectTimeout": connect_timeout}}}
        }),
    )
}

fn virtual_service(timeout: Value) -> K8sObject {
    object(
        "VirtualService",
        json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/v1"}}],
                "route": [{"destination": {
                    "host": "api.default.svc.cluster.local",
                    "port": {"number": 8080}
                }}],
                "timeout": timeout
            }]
        }),
    )
}

fn translated_connect_timeout(connect_timeout: Value) -> Result<Option<u64>, String> {
    translate_k8s_objects(&[destination_rule(connect_timeout)], options())
        .map(|translation| {
            let mesh = translation
                .config
                .mesh
                .expect("mesh present in translation");
            let rule = mesh
                .destination_rules
                .first()
                .expect("one destination rule");
            rule.traffic_policy
                .as_ref()
                .and_then(|policy| policy.connect_timeout_ms)
        })
        .map_err(|error| error.to_string())
}

#[test]
fn destination_rule_connect_timeout_refuses_values_the_data_plane_cannot_use() {
    for raw in [
        json!("5"),
        json!("five seconds"),
        json!("-1s"),
        json!(5),
        json!("0s"),
        json!("0ms"),
        json!("25h"),
    ] {
        let error = translated_connect_timeout(raw.clone())
            .expect_err("an unusable connectTimeout must refuse the DestinationRule");
        assert!(
            error.contains("connectTimeout"),
            "{raw}: expected a connectTimeout diagnostic, got {error}"
        );
    }
}

#[test]
fn destination_rule_connect_timeout_accepts_the_valid_range() {
    assert_eq!(translated_connect_timeout(json!("1ms")), Ok(Some(1)));
    assert_eq!(translated_connect_timeout(json!("250ms")), Ok(Some(250)));
    assert_eq!(
        translated_connect_timeout(json!("24h")),
        Ok(Some(MAX_TIMEOUT_MS))
    );
}

#[test]
fn virtual_service_timeout_typo_refuses_instead_of_disabling_the_timeout() {
    for raw in [json!("5"), json!("10 s"), json!("-1s"), json!(10)] {
        let error = translate_k8s_objects(&[virtual_service(raw.clone())], options())
            .map(|_| ())
            .expect_err("an unparseable route timeout must refuse the VirtualService");
        assert!(
            error.to_string().contains("timeout"),
            "{raw}: expected a timeout diagnostic, got {error}"
        );
    }
}

#[test]
fn virtual_service_timeout_still_translates_valid_values() {
    let translation = translate_k8s_objects(&[virtual_service(json!("750ms"))], options())
        .expect("a valid route timeout translates");
    assert_eq!(translation.config.proxies[0].backend_read_timeout_ms, 750);
}
