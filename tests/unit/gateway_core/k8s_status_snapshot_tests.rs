//! Structural + allocation regression for shared status-writer snapshots (#3281).

use ferrum_edge::_test_support::shared_status_objects_snapshot;
use ferrum_edge::config_sources::k8s::{K8sMetadata, K8sObject};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

const RECONCILER_SRC: &str = include_str!("../../../src/k8s_controller/reconciler.rs");

fn object(kind: &str, name: &str, payload_bytes: usize) -> K8sObject {
    K8sObject {
        api_version: "v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: json!({ "payload": "y".repeat(payload_bytes) }),
        status: Value::Object(serde_json::Map::new()),
    }
}

#[test]
fn run_status_patchers_shares_arc_slice_not_per_writer_to_vec() {
    let run_fn = RECONCILER_SRC
        .split("async fn run_status_patchers(")
        .nth(1)
        .and_then(|rest| rest.split("async fn patch_gateway_api_statuses(").next())
        .expect("run_status_patchers body");

    assert!(
        run_fn.contains("shared_status_objects_snapshot("),
        "status patchers must build one shared generation helper"
    );
    assert!(
        run_fn.contains("Arc::clone(&snapshot)"),
        "gateway writer must receive an Arc clone of the shared generation"
    );
    assert!(
        !run_fn.contains("objects.to_vec()"),
        "per-writer objects.to_vec() deep clones must not return (#3281)"
    );
    assert!(
        RECONCILER_SRC.contains("objects: Arc<[K8sObject]>"),
        "both patch helpers must accept Arc<[K8sObject]> rather than owned Vec"
    );
    assert!(
        RECONCILER_SRC.contains("plan_gateway_api_status_updates_budgeted"),
        "reconciler must use budgeted Gateway API status planning (#2397)"
    );
}

#[test]
fn shared_snapshot_none_one_and_both_writer_cases() {
    let objects = vec![object("ConfigMap", "cm", 8)];

    assert!(shared_status_objects_snapshot(&objects, false, false).is_none());

    let gateway_only = shared_status_objects_snapshot(&objects, true, false).expect("gateway");
    let istio_only = shared_status_objects_snapshot(&objects, false, true).expect("istio");
    let both = shared_status_objects_snapshot(&objects, true, true).expect("both");

    assert_eq!(Arc::strong_count(&gateway_only), 1);
    assert_eq!(Arc::strong_count(&istio_only), 1);
    assert_eq!(Arc::strong_count(&both), 1);
    assert_eq!(both.as_ref(), objects.as_slice());
}

#[test]
fn shared_snapshot_large_objects_use_refcount_not_second_deep_copy() {
    let objects = vec![object("HTTPRoute", "large", 128 * 1024)];
    let snapshot = shared_status_objects_snapshot(&objects, true, true).expect("both writers");

    let gateway_view = Arc::clone(&snapshot);
    let istio_view = Arc::clone(&snapshot);
    assert!(Arc::ptr_eq(&gateway_view, &istio_view));
    assert_eq!(Arc::strong_count(&snapshot), 3);
    assert_eq!(
        gateway_view[0].spec["payload"].as_str().map(str::len),
        Some(128 * 1024)
    );
}
