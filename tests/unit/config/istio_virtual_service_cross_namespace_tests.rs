//! Issue #7499: a mesh-bound VirtualService's `http[]` destination naming a
//! Service in another namespace is admitted only when a Gateway API
//! `ReferenceGrant` in the target namespace permits
//! `networking.istio.io/VirtualService` from the route namespace to that core
//! `Service`, the Service exists (not `ExternalName`, the port declared), and
//! its EndpointSlices pass attribution (issue #6108 parity). Every refusal
//! rejects the whole VirtualService and reports `FerrumAccepted=False` with
//! reason `RefNotPermitted`; an admitted destination is listed on the mesh
//! binding (`authorized_cross_namespace_targets`) and in the VirtualService
//! status.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sResourceKey, K8sTranslateError, K8sTranslation,
    K8sTranslationOptions, translate_k8s_objects_collecting_skips,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::istio_status::{
    VIRTUAL_SERVICE_CROSS_NAMESPACE_DESTINATIONS_NOTE, plan_istio_status_updates,
};
use ferrum_edge::modes::mesh::config::{MeshVirtualServiceHttpRoutes, MeshWaypointServiceRef};
use serde_json::{Value, json};

const ROUTE_NAMESPACE: &str = "default";
const TARGET_NAMESPACE: &str = "other";
const TARGET_HOST: &str = "ratings.other.svc.cluster.local";

/// Pod discovery off: the controller cannot attribute any EndpointSlice, so
/// every cross-namespace destination is refused as unverifiable.
fn options_without_pod_discovery() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        ROUTE_NAMESPACE.to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
    .with_source_namespaces(Vec::new())
}

/// Pod discovery on with a cluster-wide Pod watch: EndpointSlice attribution
/// can vouch for a destination's endpoints.
fn options() -> K8sTranslationOptions {
    options_without_pod_discovery().with_pod_discovery_enabled(true)
}

fn object(api_version: &str, kind: &str, name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{namespace}-{kind}-{name}"),
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

/// A selector-backed Service: Kubernetes manages its EndpointSlices.
fn service(name: &str, namespace: &str) -> K8sObject {
    object(
        "v1",
        "Service",
        name,
        namespace,
        json!({
            "selector": {"app": name},
            "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]
        }),
    )
}

fn reference_grant(namespace: &str, from: Value, to: Value) -> K8sObject {
    object(
        "gateway.networking.k8s.io/v1beta1",
        "ReferenceGrant",
        "allow-virtual-services",
        namespace,
        json!({"from": [from], "to": [to]}),
    )
}

fn virtual_service_grant() -> K8sObject {
    reference_grant(
        TARGET_NAMESPACE,
        json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
        json!({"group": "", "kind": "Service", "name": "ratings"}),
    )
}

fn virtual_service(name: &str, spec: Value) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "VirtualService",
        name,
        ROUTE_NAMESPACE,
        spec,
    )
}

fn direct_spec(host: &str) -> Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{
            "route": [{"destination": {"host": host, "port": {"number": 8080}}}]
        }]
    })
}

fn base_objects() -> Vec<K8sObject> {
    vec![
        service("reviews", ROUTE_NAMESPACE),
        service("ratings", TARGET_NAMESPACE),
    ]
}

fn translate(
    objects: &[K8sObject],
) -> (K8sTranslation, HashMap<K8sResourceKey, K8sTranslateError>) {
    translate_k8s_objects_collecting_skips(objects, options()).expect("translation runs")
}

fn refusal(skipped: &HashMap<K8sResourceKey, K8sTranslateError>, name: &str) -> Option<String> {
    skipped.iter().find_map(|(key, error)| {
        (key.kind == "VirtualService" && key.name == name).then(|| match error {
            K8sTranslateError::InvalidResource { message, .. } => message.clone(),
            other => format!("{other}"),
        })
    })
}

fn binding<'a>(
    translation: &'a K8sTranslation,
    name: &str,
) -> Option<&'a MeshVirtualServiceHttpRoutes> {
    translation.config.mesh.as_ref().and_then(|mesh| {
        mesh.virtual_service_http_routes
            .iter()
            .find(|binding| binding.name == name)
    })
}

/// `(status, reason, message, detail)` of the VirtualService's
/// `FerrumAccepted` condition.
fn accepted_condition(objects: &[K8sObject], name: &str) -> (String, String, String, Value) {
    let updates = plan_istio_status_updates(objects, options());
    let update = updates
        .iter()
        .find(|update| update.kind == "VirtualService" && update.name == name)
        .unwrap_or_else(|| panic!("status update for {name}"));
    let condition = update.status["conditions"]
        .as_array()
        .expect("conditions")
        .iter()
        .find(|condition| condition["type"] == "FerrumAccepted")
        .expect("FerrumAccepted condition")
        .clone();
    (
        condition["status"].as_str().unwrap_or_default().to_string(),
        condition["reason"].as_str().unwrap_or_default().to_string(),
        condition["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        update.ferrum_detail.clone().unwrap_or(Value::Null),
    )
}

/// Assert `name` is refused fail-closed: no binding, no route proxy, and
/// `FerrumAccepted=False`/`RefNotPermitted`. Returns the refusal message.
fn assert_refused(objects: &[K8sObject], name: &str) -> String {
    let (translation, skipped) = translate(objects);
    let message = refusal(&skipped, name)
        .unwrap_or_else(|| panic!("VirtualService {name} must be refused: {skipped:?}"));
    assert!(
        message.contains("cross-namespace VirtualService destination is not permitted"),
        "{name}: {message}"
    );
    assert!(binding(&translation, name).is_none(), "{name}: no binding");
    assert!(
        !translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.id.starts_with("istio-vs-default-") && proxy.id.contains(name)),
        "{name}: no partial route is emitted"
    );
    let (status, reason, _, _) = accepted_condition(objects, name);
    assert_eq!(status, "False", "{name}");
    assert_eq!(reason, "RefNotPermitted", "{name}");
    message
}

#[test]
fn a_granted_cross_namespace_destination_is_admitted_and_reported() {
    let mut objects = base_objects();
    objects.push(virtual_service_grant());
    objects.push(virtual_service("direct", direct_spec(TARGET_HOST)));
    let (translation, skipped) = translate(&objects);
    assert!(refusal(&skipped, "direct").is_none(), "{skipped:?}");
    let binding = binding(&translation, "direct").expect("mesh binding");
    assert_eq!(
        binding.authorized_cross_namespace_targets,
        vec![MeshWaypointServiceRef {
            namespace: TARGET_NAMESPACE.to_string(),
            name: "ratings".to_string(),
        }]
    );

    let (status, reason, message, detail) = accepted_condition(&objects, "direct");
    assert_eq!(status, "True");
    assert_eq!(reason, "Accepted");
    assert!(
        message.contains(VIRTUAL_SERVICE_CROSS_NAMESPACE_DESTINATIONS_NOTE),
        "the accepted message says where the destination is routed: {message}"
    );
    assert_eq!(
        detail["translation"]["cross_namespace_destinations"],
        json!(["other/ratings"])
    );
}

#[test]
fn every_service_alias_form_naming_another_namespace_needs_the_grant() {
    for host in [
        "ratings.other",
        "ratings.other.svc",
        "ratings.other.svc.cluster.local",
        "Ratings.Other.svc.cluster.local.",
    ] {
        let mut objects = base_objects();
        objects.push(virtual_service("alias", direct_spec(host)));
        let message = assert_refused(&objects, "alias");
        assert!(message.contains("ReferenceGrant"), "{host}: {message}");

        objects.push(virtual_service_grant());
        let (translation, skipped) = translate(&objects);
        assert!(refusal(&skipped, "alias").is_none(), "{host}: {skipped:?}");
        assert_eq!(
            binding(&translation, "alias")
                .expect("binding")
                .authorized_cross_namespace_targets
                .len(),
            1,
            "{host}"
        );
    }
}

#[test]
fn a_mismatched_reference_grant_fails_closed() {
    let grants = [
        (
            "wrong from namespace",
            reference_grant(
                TARGET_NAMESPACE,
                json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": "elsewhere"}),
                json!({"group": "", "kind": "Service"}),
            ),
        ),
        (
            "wrong from kind",
            reference_grant(
                TARGET_NAMESPACE,
                json!({"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": ROUTE_NAMESPACE}),
                json!({"group": "", "kind": "Service"}),
            ),
        ),
        (
            "wrong from group",
            reference_grant(
                TARGET_NAMESPACE,
                json!({"group": "", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
                json!({"group": "", "kind": "Service"}),
            ),
        ),
        (
            "wrong target name",
            reference_grant(
                TARGET_NAMESPACE,
                json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
                json!({"group": "", "kind": "Service", "name": "details"}),
            ),
        ),
        (
            "wrong target kind",
            reference_grant(
                TARGET_NAMESPACE,
                json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
                json!({"group": "", "kind": "Secret"}),
            ),
        ),
        (
            "grant in the route namespace",
            reference_grant(
                ROUTE_NAMESPACE,
                json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
                json!({"group": "", "kind": "Service"}),
            ),
        ),
    ];
    for (case, grant) in grants {
        let mut objects = base_objects();
        objects.push(grant);
        objects.push(virtual_service("direct", direct_spec(TARGET_HOST)));
        let message = assert_refused(&objects, "direct");
        assert!(message.contains("ReferenceGrant"), "{case}: {message}");
    }
}

#[test]
fn a_grant_without_a_target_name_admits_every_service_in_its_namespace() {
    let mut objects = base_objects();
    objects.push(reference_grant(
        TARGET_NAMESPACE,
        json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
        json!({"group": "", "kind": "Service"}),
    ));
    objects.push(virtual_service("direct", direct_spec(TARGET_HOST)));
    let (translation, skipped) = translate(&objects);
    assert!(refusal(&skipped, "direct").is_none(), "{skipped:?}");
    assert!(binding(&translation, "direct").is_some());
}

#[test]
fn a_missing_target_service_or_port_fails_closed() {
    // No `other/ratings` Service at all (or outside the control plane's
    // watch scope): the grant alone admits nothing.
    let objects = vec![
        service("reviews", ROUTE_NAMESPACE),
        virtual_service_grant(),
        virtual_service("direct", direct_spec(TARGET_HOST)),
    ];
    let message = assert_refused(&objects, "direct");
    assert!(message.contains("Service inventory"), "{message}");

    let mut objects = base_objects();
    objects.push(virtual_service_grant());
    objects.push(virtual_service(
        "direct",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{"route": [{"destination": {"host": TARGET_HOST, "port": {"number": 9999}}}]}]
        }),
    ));
    let message = assert_refused(&objects, "direct");
    assert!(message.contains("does not declare port"), "{message}");
}

#[test]
fn an_external_name_target_fails_closed_even_when_granted() {
    let objects = vec![
        service("reviews", ROUTE_NAMESPACE),
        object(
            "v1",
            "Service",
            "ratings",
            TARGET_NAMESPACE,
            json!({
                "type": "ExternalName",
                "externalName": "payroll.tenant-c.svc.cluster.local",
                "ports": [{"name": "http", "port": 8080}]
            }),
        ),
        virtual_service_grant(),
        virtual_service("direct", direct_spec(TARGET_HOST)),
    ];
    let message = assert_refused(&objects, "direct");
    assert!(message.contains("ExternalName"), "{message}");
}

#[test]
fn every_leg_is_checked_including_zero_weight_and_dispatch_branches() {
    let specs = [
        (
            "zero-weight",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{"route": [
                    {"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 100},
                    {"destination": {"host": TARGET_HOST, "port": {"number": 8080}}, "weight": 0}
                ]}]
            }),
        ),
        (
            "branch",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [
                    {
                        "match": [{"headers": {"x-version": {"exact": "v2"}}}],
                        "route": [{"destination": {"host": TARGET_HOST, "port": {"number": 8080}}}]
                    },
                    {"route": [{"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}}]}
                ]
            }),
        ),
        (
            "split",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{"route": [
                    {"destination": {"host": "reviews.default.svc.cluster.local", "port": {"number": 8080}}, "weight": 90},
                    {"destination": {"host": TARGET_HOST, "port": {"number": 8080}}, "weight": 10}
                ]}]
            }),
        ),
    ];
    for (name, spec) in specs {
        let mut objects = base_objects();
        objects.push(virtual_service(name, spec));
        assert_refused(&objects, name);
    }
}

#[test]
fn a_gateway_only_virtual_service_is_not_gated() {
    // Bound only to an ingress gateway: its routes never ride a mesh slice,
    // and Istio ingress routing to another namespace's Service needs no grant.
    let mut spec = direct_spec(TARGET_HOST);
    spec["gateways"] = json!(["istio-system/public"]);
    let mut objects = base_objects();
    objects.push(virtual_service("ingress", spec));
    let (translation, skipped) = translate(&objects);
    assert!(refusal(&skipped, "ingress").is_none(), "{skipped:?}");
    assert!(binding(&translation, "ingress").is_none());
    let (status, _, message, _) = accepted_condition(&objects, "ingress");
    assert_eq!(status, "True");
    assert!(!message.contains(VIRTUAL_SERVICE_CROSS_NAMESPACE_DESTINATIONS_NOTE));
}

#[test]
fn a_relative_two_label_host_is_a_service_reference_even_without_inventory() {
    // The control plane holds no Service in `beta`, yet a gateway pod's DNS
    // search suffix completes `ratings.beta` to `beta/ratings`: the host is
    // gated exactly like the fully qualified form, and the refusal says which
    // rule made it a Service reference.
    let mut objects = base_objects();
    objects.push(virtual_service("unwatched", direct_spec("ratings.beta")));
    let message = assert_refused(&objects, "unwatched");
    assert!(message.contains("ReferenceGrant"), "{message}");
    assert!(message.contains("relative two-label host"), "{message}");

    // A relative two-label external name is refused the same way.
    let mut objects = base_objects();
    objects.push(virtual_service("external", direct_spec("httpbin.org")));
    let message = assert_refused(&objects, "external");
    assert!(message.contains("relative two-label host"), "{message}");
    assert!(message.contains("trailing dot"), "{message}");
}

#[test]
fn an_absolute_two_label_external_host_is_not_a_service_reference() {
    // A trailing dot makes the name absolute: no search suffix completes it.
    let mut objects = base_objects();
    objects.push(virtual_service("external", direct_spec("httpbin.org.")));
    let (translation, skipped) = translate(&objects);
    assert!(refusal(&skipped, "external").is_none(), "{skipped:?}");
    assert!(
        binding(&translation, "external")
            .expect("binding")
            .authorized_cross_namespace_targets
            .is_empty()
    );
}

#[test]
fn a_mesh_and_gateway_virtual_service_refuses_the_gateway_leg_too() {
    // Bound to `mesh` and a gateway: the refusal rejects the whole
    // VirtualService, so no gateway proxy reaches the ungranted Service.
    let mut spec = direct_spec("ratings.beta");
    spec["gateways"] = json!(["mesh", "istio-system/public"]);
    let mut objects = base_objects();
    objects.push(virtual_service("mixed", spec));
    assert_refused(&objects, "mixed");
    let (translation, _) = translate(&objects);
    assert!(
        !translation
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_host.contains("ratings.beta")),
        "no gateway proxy dials the ungranted Service"
    );
}

#[test]
fn a_gateway_only_virtual_service_keeps_istio_ingress_semantics_for_two_label_hosts() {
    // Gateway-only routes are not mesh-bound and are not gated, whatever the
    // destination form (the fully qualified form is not gated either).
    let mut spec = direct_spec("ratings.beta");
    spec["gateways"] = json!(["istio-system/public"]);
    let mut objects = base_objects();
    objects.push(virtual_service("ingress", spec));
    let (_, skipped) = translate(&objects);
    assert!(refusal(&skipped, "ingress").is_none(), "{skipped:?}");
}

#[test]
fn a_missing_named_port_is_a_reference_refusal() {
    let mut objects = base_objects();
    objects.push(virtual_service_grant());
    objects.push(virtual_service(
        "named",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{"route": [{"destination": {"host": TARGET_HOST, "port": {"name": "grpc"}}}]}]
        }),
    ));
    let message = assert_refused(&objects, "named");
    assert!(message.contains("port named"), "{message}");
}

/// Review F7 (round 5): a named port resolves in route translation exactly
/// as admission resolved it, under every custom-domain spelling admission
/// accepts (case folded, a root dot on the host and on the configured domain).
#[test]
fn a_named_port_resolves_under_every_admitted_custom_domain_spelling() {
    for domain in ["Corp.Example.", "corp.example"] {
        for host in [
            "ratings.other.svc.corp.example",
            "ratings.other.svc.corp.example.",
            "Ratings.Other.Svc.Corp.Example",
            "ratings.other.svc",
            "ratings.other",
        ] {
            let mut objects = base_objects();
            objects.push(virtual_service_grant());
            objects.push(virtual_service(
                "named",
                json!({
                    "hosts": ["reviews.default.svc.cluster.local"],
                    "http": [{"route": [{"destination": {"host": host, "port": {"name": "http"}}}]}]
                }),
            ));
            let (translation, skipped) = translate_k8s_objects_collecting_skips(
                &objects,
                options().with_cluster_domain(domain.to_string()),
            )
            .expect("translation runs");
            assert!(
                refusal(&skipped, "named").is_none(),
                "{domain:?} {host:?}: {skipped:?}"
            );
            let binding = binding(&translation, "named")
                .unwrap_or_else(|| panic!("{domain:?} {host:?}: mesh binding"));
            assert_eq!(
                binding.authorized_cross_namespace_targets,
                vec![MeshWaypointServiceRef {
                    namespace: TARGET_NAMESPACE.to_string(),
                    name: "ratings".to_string(),
                }],
                "{domain:?} {host:?}"
            );
        }
    }
}

#[test]
fn more_than_the_binding_budget_of_target_services_is_refused() {
    let limit = ferrum_edge::modes::mesh::config::MAX_VIRTUAL_SERVICE_CROSS_NAMESPACE_TARGETS;
    let mut objects = vec![service("reviews", ROUTE_NAMESPACE)];
    let mut http = Vec::new();
    for index in 0..=limit {
        let name = format!("svc-{index}");
        objects.push(service(&name, TARGET_NAMESPACE));
        http.push(json!({
            "match": [{"headers": {"x-target": {"exact": name.clone()}}}],
            "route": [{"destination": {
                "host": format!("{name}.other.svc.cluster.local"),
                "port": {"number": 8080}
            }}]
        }));
    }
    objects.push(reference_grant(
        TARGET_NAMESPACE,
        json!({"group": "networking.istio.io", "kind": "VirtualService", "namespace": ROUTE_NAMESPACE}),
        json!({"group": "", "kind": "Service"}),
    ));
    objects.push(virtual_service(
        "wide",
        json!({"hosts": ["reviews.default.svc.cluster.local"], "http": http}),
    ));
    let message = assert_refused(&objects, "wide");
    assert!(message.contains("distinct Services"), "{message}");
}

#[test]
fn a_same_namespace_destination_needs_no_grant() {
    let mut objects = base_objects();
    objects.push(virtual_service(
        "local",
        direct_spec("reviews.default.svc.cluster.local"),
    ));
    let (translation, skipped) = translate(&objects);
    assert!(refusal(&skipped, "local").is_none(), "{skipped:?}");
    assert!(
        binding(&translation, "local")
            .expect("binding")
            .authorized_cross_namespace_targets
            .is_empty()
    );
}

#[test]
fn reference_grant_changes_are_reevaluated_on_every_translation() {
    // Translation is a pure function of the snapshot the controller
    // reconciles on every ReferenceGrant / Service / EndpointSlice event:
    // adding the grant admits, deleting it refuses again.
    let mut objects = base_objects();
    objects.push(virtual_service("direct", direct_spec(TARGET_HOST)));
    assert_refused(&objects, "direct");
    objects.push(virtual_service_grant());
    let (translation, skipped) = translate(&objects);
    assert!(refusal(&skipped, "direct").is_none());
    assert!(binding(&translation, "direct").is_some());
    objects.retain(|object| object.kind != "ReferenceGrant");
    assert_refused(&objects, "direct");
}

// --- EndpointSlice attribution (issue #6108 parity) ------------------------

fn discovery_options() -> K8sTranslationOptions {
    options().with_pod_discovery_enabled(true)
}

fn pod(namespace: &str, name: &str, ip: &str) -> K8sObject {
    let mut pod = object("v1", "Pod", name, namespace, json!({}));
    pod.status = json!({"phase": "Running", "podIP": ip});
    pod
}

fn node() -> K8sObject {
    let mut node = object(
        "v1",
        "Node",
        "worker-1",
        "",
        json!({"podCIDRs": ["10.244.3.0/24"]}),
    );
    node.status = json!({"addresses": [{"type": "InternalIP", "address": "192.168.10.5"}]});
    node
}

fn ratings_slice(address: &str) -> K8sObject {
    let mut slice = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "ratings-manual",
        TARGET_NAMESPACE,
        json!({
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": 8080}],
            "endpoints": [{"addresses": [address], "conditions": {"ready": true}}]
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        "ratings".to_string(),
    );
    slice
}

fn selectorless_ratings() -> K8sObject {
    object(
        "v1",
        "Service",
        "ratings",
        TARGET_NAMESPACE,
        json!({
            "clusterIP": "10.96.0.50",
            "ports": [{"name": "http", "port": 8080, "targetPort": 8080}]
        }),
    )
}

fn assert_refused_with(objects: &[K8sObject], options: K8sTranslationOptions, expected: &str) {
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(objects, options).expect("translation runs");
    let message = refusal(&skipped, "direct")
        .unwrap_or_else(|| panic!("refused for {expected}: {skipped:?}"));
    assert!(message.contains(expected), "{expected}: {message}");
    assert!(binding(&translation, "direct").is_none());
}

#[test]
fn a_foreign_endpoint_fails_closed() {
    // The slice points `other/ratings` at a Pod of a third namespace.
    let objects = vec![
        service("reviews", ROUTE_NAMESPACE),
        selectorless_ratings(),
        pod("tenant-c", "payroll", "10.2.0.20"),
        ratings_slice("10.2.0.20"),
        virtual_service_grant(),
        virtual_service("direct", direct_spec(TARGET_HOST)),
    ];
    assert_refused_with(&objects, discovery_options(), "ForeignEndpoint");
}

#[test]
fn an_unattributed_endpoint_fails_closed_and_the_opt_in_never_widens_it() {
    let objects = vec![
        service("reviews", ROUTE_NAMESPACE),
        selectorless_ratings(),
        node(),
        ratings_slice("203.0.113.10"),
        virtual_service_grant(),
        virtual_service("direct", direct_spec(TARGET_HOST)),
    ];
    assert_refused_with(&objects, discovery_options(), "UnattributedEndpoint");
    // FERRUM_K8S_ALLOW_SELECTORLESS_EXTERNAL_ENDPOINTS admits such endpoints
    // for same-namespace references only, never across a ReferenceGrant.
    assert_refused_with(
        &objects,
        discovery_options().with_selectorless_external_endpoints_allowed(true),
        "UnattributedEndpoint",
    );
}

#[test]
fn an_unverifiable_selectorless_target_fails_closed() {
    // Pod discovery off: nothing can check a selector-less Service's slices.
    let objects = vec![
        service("reviews", ROUTE_NAMESPACE),
        selectorless_ratings(),
        ratings_slice("10.1.0.20"),
        virtual_service_grant(),
        virtual_service("direct", direct_spec(TARGET_HOST)),
    ];
    assert_refused_with(&objects, options_without_pod_discovery(), "Unverifiable");
}

/// Review F1 (round 5): a selector-backed destination whose slices the
/// controller cannot attribute (pod discovery off, or its namespace outside
/// the Pod watch scope) is refused too. A dual-bound VirtualService's gateway
/// leg dials the Service's DNS name, and Kubernetes Service routing follows
/// every EndpointSlice labelled with it, selector or not.
#[test]
fn an_unverifiable_selector_backed_target_fails_closed() {
    // The manual slice points the selector-backed `other/ratings` at an
    // address a third namespace owns; nothing here can see it.
    let mesh_and_gateway = json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "gateways": ["mesh", "default/edge"],
        "http": [{
            "route": [{"destination": {"host": TARGET_HOST, "port": {"number": 8080}}}]
        }]
    });
    for spec in [direct_spec(TARGET_HOST), mesh_and_gateway] {
        let objects = vec![
            service("reviews", ROUTE_NAMESPACE),
            service("ratings", TARGET_NAMESPACE),
            ratings_slice("10.2.0.20"),
            virtual_service_grant(),
            virtual_service("direct", spec),
        ];
        assert_refused_with(&objects, options_without_pod_discovery(), "Unverifiable");
        // The Pod watch covers only the route namespace.
        assert_refused_with(
            &objects,
            options_without_pod_discovery()
                .with_pod_discovery_enabled(true)
                .with_pod_source_namespaces(vec![ROUTE_NAMESPACE.to_string()]),
            "Unverifiable",
        );
    }
}

#[test]
fn a_target_whose_endpoints_are_its_own_pods_is_admitted() {
    let objects = vec![
        service("reviews", ROUTE_NAMESPACE),
        selectorless_ratings(),
        pod(TARGET_NAMESPACE, "ratings-0", "10.1.0.20"),
        ratings_slice("10.1.0.20"),
        virtual_service_grant(),
        virtual_service("direct", direct_spec(TARGET_HOST)),
    ];
    let (translation, skipped) =
        translate_k8s_objects_collecting_skips(&objects, discovery_options())
            .expect("translation runs");
    assert!(refusal(&skipped, "direct").is_none(), "{skipped:?}");
    assert!(binding(&translation, "direct").is_some());
}
