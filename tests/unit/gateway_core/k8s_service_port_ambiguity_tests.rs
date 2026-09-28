//! A Service that declares one port number for both an HTTP-family port and a
//! raw-TCP port is refused on its own: both ports would route cross-cluster on
//! the same `p<port>` east-west SNI alias. Sibling Services still translate.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_pod_discovery_enabled(true)
}

fn service(name: &str, ports: Value) -> K8sObject {
    K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec: json!({ "ports": ports }),
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translated_service_names(objects: &[K8sObject]) -> (Vec<String>, Vec<String>) {
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(objects, options()).expect("translation");
    let names: Vec<String> = translation
        .config
        .mesh
        .map(|mesh| mesh.services.iter().map(|svc| svc.name.clone()).collect())
        .unwrap_or_default();
    let errors: Vec<String> = skipped
        .into_iter()
        .map(|(key, error)| format!("{}: {error}", key.name))
        .collect();
    (names, errors)
}

#[test]
fn http_and_raw_tcp_ports_sharing_a_number_refuse_only_that_service() {
    let objects = vec![
        service(
            "ambiguous",
            json!([
                {"name": "http", "port": 7070, "protocol": "TCP", "appProtocol": "http"},
                {"name": "raw", "port": 7070, "protocol": "TCP", "appProtocol": "tcp"}
            ]),
        ),
        service(
            "reviews",
            json!([{"name": "http", "port": 9080, "protocol": "TCP"}]),
        ),
    ];

    let (names, errors) = translated_service_names(&objects);

    assert!(names.iter().any(|name| name == "reviews"), "{names:?}");
    assert!(!names.iter().any(|name| name == "ambiguous"), "{names:?}");
    assert!(
        errors
            .iter()
            .any(|error| error.starts_with("ambiguous:") && error.contains("port \"7070\"")),
        "the refusal must name the Service and the ambiguous port, got {errors:?}"
    );
}

#[test]
fn udp_port_sharing_an_http_port_number_is_not_ambiguous() {
    // UDP routes on its own `p<port>-udp` alias, so HTTP + UDP on 443 is fine.
    let objects = vec![service(
        "web",
        json!([
            {"name": "https", "port": 443, "protocol": "TCP", "appProtocol": "http"},
            {"name": "quic", "port": 443, "protocol": "UDP"}
        ]),
    )];

    let (names, errors) = translated_service_names(&objects);

    assert!(names.iter().any(|name| name == "web"), "{names:?}");
    assert!(errors.is_empty(), "{errors:?}");
}
