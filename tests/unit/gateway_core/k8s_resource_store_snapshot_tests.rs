//! Deterministic reconcile snapshots (issue #4491).
//!
//! `ResourceStoreSet::snapshot_all` feeds every reconcile. A reflector store
//! iterates a hash map, and a scope whose stream ended re-registers at the end
//! of the store list, so without an explicit rule the same cluster state could
//! translate differently from one reconcile to the next — including which
//! served API version of one object the translator sees. These tests pin the
//! rule: one object per `(group, kind, namespace, name)`, the preferred served
//! version among aliases by Kubernetes version priority (GA, then beta, then
//! alpha), ordered by group, kind, namespace, name, whatever order the stores
//! were registered in.

use std::sync::Arc;

use ferrum_edge::k8s_controller::resource_store::{CrdResourceStore, ResourceStoreSet};
use kube::api::{ApiResource, DynamicObject};
use kube::runtime::reflector;
use kube::runtime::watcher::Event;
use serde_json::json;

fn resource(group: &str, version: &str, kind: &str) -> ApiResource {
    ApiResource {
        group: group.to_string(),
        version: version.to_string(),
        api_version: if group.is_empty() {
            version.to_string()
        } else {
            format!("{group}/{version}")
        },
        kind: kind.to_string(),
        plural: format!("{}s", kind.to_ascii_lowercase()),
    }
}

/// A store that has completed its initial list with `objects`, each given as
/// `(namespace, name)`; `None` is a cluster-scoped object.
fn populated_store(
    resource: &ApiResource,
    scope: &str,
    objects: &[(Option<&str>, &str)],
) -> Arc<CrdResourceStore> {
    let mut writer = reflector::store::Writer::new(resource.clone());
    writer.apply_watcher_event(&Event::Init);
    for (namespace, name) in objects {
        let mut object = DynamicObject::new(name, resource);
        object.data = json!({ "spec": {} });
        if let Some(namespace) = namespace {
            object = object.within(namespace);
        }
        writer.apply_watcher_event(&Event::InitApply(object));
    }
    writer.apply_watcher_event(&Event::InitDone);
    Arc::new(CrdResourceStore::new_scoped(
        resource.api_version.clone(),
        resource.kind.clone(),
        scope.to_string(),
        writer.as_reader(),
    ))
}

/// Register a populated store, asserting the scope was not already taken.
fn register(
    set: &mut ResourceStoreSet,
    resource: &ApiResource,
    scope: &str,
    objects: &[(Option<&str>, &str)],
) {
    assert!(
        set.add_store(populated_store(resource, scope, objects)),
        "{} {} {scope} registered twice",
        resource.api_version,
        resource.kind
    );
}

fn snapshot_keys(set: &ResourceStoreSet) -> Vec<(String, String, String, String)> {
    set.snapshot_all()
        .into_iter()
        .map(|object| {
            (
                object.api_version,
                object.kind,
                object.metadata.namespace,
                object.metadata.name,
            )
        })
        .collect()
}

#[test]
fn snapshot_all_order_is_independent_of_store_registration_order() {
    let gateways = resource("gateway.networking.k8s.io", "v1", "Gateway");
    let routes = resource("gateway.networking.k8s.io", "v1", "HTTPRoute");
    let secrets = resource("", "v1", "Secret");
    let objects = |resource: &ApiResource| {
        populated_store(
            resource,
            "namespace:gateway-conformance-infra",
            &[
                (Some("gateway-conformance-infra"), "zeta"),
                (Some("gateway-conformance-infra"), "alpha"),
                (Some("gateway-conformance-app-backend"), "mid"),
            ],
        )
    };

    let mut forward = ResourceStoreSet::new();
    assert!(forward.add_store(objects(&gateways)));
    assert!(forward.add_store(objects(&routes)));
    assert!(forward.add_store(objects(&secrets)));

    let mut reverse = ResourceStoreSet::new();
    assert!(reverse.add_store(objects(&secrets)));
    assert!(reverse.add_store(objects(&routes)));
    assert!(reverse.add_store(objects(&gateways)));

    let forward_keys = snapshot_keys(&forward);
    assert_eq!(forward_keys, snapshot_keys(&reverse));

    let key = |api_version: &str, kind: &str, namespace: &str, name: &str| {
        (
            api_version.to_string(),
            kind.to_string(),
            namespace.to_string(),
            name.to_string(),
        )
    };
    assert_eq!(
        forward_keys,
        vec![
            // The core group sorts before every named group.
            key("v1", "Secret", "gateway-conformance-app-backend", "mid"),
            key("v1", "Secret", "gateway-conformance-infra", "alpha"),
            key("v1", "Secret", "gateway-conformance-infra", "zeta"),
            key(
                "gateway.networking.k8s.io/v1",
                "Gateway",
                "gateway-conformance-app-backend",
                "mid",
            ),
            key(
                "gateway.networking.k8s.io/v1",
                "Gateway",
                "gateway-conformance-infra",
                "alpha",
            ),
            key(
                "gateway.networking.k8s.io/v1",
                "Gateway",
                "gateway-conformance-infra",
                "zeta",
            ),
            key(
                "gateway.networking.k8s.io/v1",
                "HTTPRoute",
                "gateway-conformance-app-backend",
                "mid",
            ),
            key(
                "gateway.networking.k8s.io/v1",
                "HTTPRoute",
                "gateway-conformance-infra",
                "alpha",
            ),
            key(
                "gateway.networking.k8s.io/v1",
                "HTTPRoute",
                "gateway-conformance-infra",
                "zeta",
            ),
        ],
        "group, kind, namespace, name — never store or hash-map order"
    );
}

#[test]
fn served_version_aliases_collapse_onto_the_preferred_version_in_any_order() {
    let gateway_v1 = resource("gateway.networking.k8s.io", "v1", "Gateway");
    let gateway_v1beta1 = resource("gateway.networking.k8s.io", "v1beta1", "Gateway");
    let tlsroute_v1 = resource("gateway.networking.k8s.io", "v1", "TLSRoute");
    let tlsroute_v1alpha2 = resource("gateway.networking.k8s.io", "v1alpha2", "TLSRoute");
    let edge = &[(Some("default"), "edge")];

    // The compatibility versions register FIRST here — the order a reprobe
    // produces after a v1 stream ended and re-registered at the end.
    let mut set = ResourceStoreSet::new();
    register(&mut set, &gateway_v1beta1, "all", edge);
    register(&mut set, &tlsroute_v1alpha2, "all", edge);
    register(&mut set, &gateway_v1, "all", edge);
    register(&mut set, &tlsroute_v1, "all", edge);

    let objects = set.snapshot_all();
    assert_eq!(objects.len(), 2, "one object per identity");
    assert!(
        objects
            .iter()
            .all(|object| object.api_version == "gateway.networking.k8s.io/v1"),
        "the GA version wins regardless of registration order: {:?}",
        objects
            .iter()
            .map(|object| (&object.kind, &object.api_version))
            .collect::<Vec<_>>()
    );
    assert_eq!(objects[0].kind, "Gateway");
    assert_eq!(objects[1].kind, "TLSRoute");
}

/// The preference is Kubernetes version priority, not string order, so the
/// invariant survives the first alias pair that is not GA `v1` against a
/// `v1{alpha,beta}N` sibling: `v2` beats `v1beta1` (string order would pick
/// `v1beta1`), a GA `v1` beats a newer `v2alpha1`, and `v1beta2` beats
/// `v1beta1`.
#[test]
fn served_version_preference_is_kubernetes_version_priority_not_string_order() {
    let widget_v2 = resource("example.com", "v2", "Widget");
    let widget_v1beta1 = resource("example.com", "v1beta1", "Widget");
    let gadget_v1 = resource("example.com", "v1", "Gadget");
    let gadget_v2alpha1 = resource("example.com", "v2alpha1", "Gadget");
    let gizmo_v1beta1 = resource("example.com", "v1beta1", "Gizmo");
    let gizmo_v1beta2 = resource("example.com", "v1beta2", "Gizmo");
    let one = &[(Some("default"), "one")];

    for reversed in [false, true] {
        let mut aliases = vec![
            &widget_v1beta1,
            &widget_v2,
            &gadget_v2alpha1,
            &gadget_v1,
            &gizmo_v1beta1,
            &gizmo_v1beta2,
        ];
        if reversed {
            aliases.reverse();
        }
        let mut set = ResourceStoreSet::new();
        for alias in aliases {
            register(&mut set, alias, "all", one);
        }

        let chosen: Vec<(String, String)> = set
            .snapshot_all()
            .into_iter()
            .map(|object| (object.kind, object.api_version))
            .collect();
        assert_eq!(
            chosen,
            vec![
                ("Gadget".to_string(), "example.com/v1".to_string()),
                ("Gizmo".to_string(), "example.com/v1beta2".to_string()),
                ("Widget".to_string(), "example.com/v2".to_string()),
            ],
            "reversed registration: {reversed}"
        );
    }
}

#[test]
fn store_for_scope_and_object_identities_read_the_registered_scope() {
    let routes = resource("gateway.networking.k8s.io", "v1alpha2", "TCPRoute");
    let classes = resource("gateway.networking.k8s.io", "v1", "GatewayClass");
    let mut set = ResourceStoreSet::new();
    register(
        &mut set,
        &routes,
        "namespace:gateway-conformance-infra",
        &[
            (Some("gateway-conformance-infra"), "blackbox-tcp-main"),
            (Some("gateway-conformance-infra"), "blackbox-tcp-delete"),
        ],
    );
    register(&mut set, &classes, "all", &[(None, "ferrum")]);

    let store = set
        .store_for_scope(
            "gateway.networking.k8s.io/v1alpha2",
            "TCPRoute",
            "namespace:gateway-conformance-infra",
        )
        .expect("registered scope");
    let mut identities = store.object_identities();
    identities.sort();
    assert_eq!(
        identities,
        vec![
            (
                "gateway-conformance-infra".to_string(),
                "blackbox-tcp-delete".to_string(),
            ),
            (
                "gateway-conformance-infra".to_string(),
                "blackbox-tcp-main".to_string(),
            ),
        ]
    );

    let cluster_scoped = set
        .store_for_scope("gateway.networking.k8s.io/v1", "GatewayClass", "all")
        .expect("registered cluster-scoped scope");
    assert_eq!(
        cluster_scoped.object_identities(),
        vec![(String::new(), "ferrum".to_string())],
        "cluster-scoped objects carry an empty namespace"
    );

    let missing = set.store_for_scope(
        "gateway.networking.k8s.io/v1alpha2",
        "TCPRoute",
        "namespace:other",
    );
    assert!(
        missing.is_none(),
        "a scope that was never registered has no store"
    );
    let wrong_version = set.store_for_scope("gateway.networking.k8s.io/v1", "TCPRoute", "all");
    assert!(
        wrong_version.is_none(),
        "the lookup is exact on api_version as well"
    );
}
