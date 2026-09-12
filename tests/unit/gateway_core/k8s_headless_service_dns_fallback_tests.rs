//! Headless Service DNS fallback must dial `targetPort`, not `service_port`.
//!
//! Gateway API conformance `HTTPRouteServiceTypes` creates selectorless
//! headless Services with empty manual EndpointSlices, accepts the HTTPRoute,
//! then patches the slices with pod IPs. When first translation still sees
//! empty slices, Ferrum falls back to Service DNS. CoreDNS later returns the
//! pod IP; the container listens on `targetPort` (3000), not `port` (8080).
//! Selectorless ClusterIP Services keep `port` because kube-proxy DNAT maps it.

use std::collections::HashMap;

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
    .with_pod_discovery_enabled(true)
}

fn object(kind: &str, api_version: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
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
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn http_route(path: &str, backend: &str) -> K8sObject {
    object(
        "HTTPRoute",
        "gateway.networking.k8s.io/v1",
        "service-types",
        json!({
            "rules": [{
                "matches": [{"path": {"type": "Exact", "value": path}}],
                "backendRefs": [{"name": backend, "port": 8080}]
            }]
        }),
    )
}

fn service(name: &str, spec: Value) -> K8sObject {
    object("Service", "v1", name, spec)
}

fn empty_manual_slice(service_name: &str) -> K8sObject {
    let mut slice = object(
        "EndpointSlice",
        "discovery.k8s.io/v1",
        &format!("{service_name}-ip4"),
        json!({
            "addressType": "IPv4",
            "ports": [{
                "name": "first-port",
                "port": 3000,
                "protocol": "TCP"
            }],
            "endpoints": []
        }),
    );
    slice.metadata.labels.insert(
        "kubernetes.io/service-name".to_string(),
        service_name.to_string(),
    );
    slice
}

fn ready_manual_slice(service_name: &str, address: &str) -> K8sObject {
    let mut slice = empty_manual_slice(service_name);
    slice.spec["endpoints"] = json!([{
        "addresses": [address],
        "conditions": {"ready": true, "serving": true, "terminating": false}
    }]);
    slice
}

fn headless_service(name: &str, target_port: Value) -> K8sObject {
    service(
        name,
        json!({
            "clusterIP": "None",
            "ports": [{
                "name": "first-port",
                "protocol": "TCP",
                "port": 8080,
                "targetPort": target_port
            }]
        }),
    )
}

#[test]
fn headless_manual_endpointslices_without_ready_addresses_dial_target_port() {
    let result = translate_k8s_objects(
        &[
            headless_service("headless-manual-endpointslices", json!(3000)),
            empty_manual_slice("headless-manual-endpointslices"),
            http_route(
                "/headless-manual-endpointslices",
                "headless-manual-endpointslices",
            ),
        ],
        options(),
    )
    .expect("headless Service with empty manual EndpointSlices should translate");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(
        proxy.backend_host, "headless-manual-endpointslices.default.svc.cluster.local",
        "empty slices must fall back to headless Service DNS so CoreDNS can publish later pod IPs"
    );
    assert_eq!(
        proxy.backend_port, 3000,
        "headless DNS names resolve to pod IPs that listen on targetPort, not service port"
    );
    assert!(
        result.config.upstreams.is_empty(),
        "DNS fallback is a single backend, not an upstream"
    );
}

#[test]
fn selectorless_cluster_ip_without_ready_addresses_keeps_service_port() {
    let result = translate_k8s_objects(
        &[
            service(
                "manual-endpointslices",
                json!({
                    "clusterIP": "10.96.44.109",
                    "ports": [{
                        "name": "first-port",
                        "protocol": "TCP",
                        "port": 8080,
                        "targetPort": 3000
                    }]
                }),
            ),
            empty_manual_slice("manual-endpointslices"),
            http_route("/manual-endpointslices", "manual-endpointslices"),
        ],
        options(),
    )
    .expect("selectorless ClusterIP with empty EndpointSlices should translate");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(
        proxy.backend_host,
        "manual-endpointslices.default.svc.cluster.local"
    );
    assert_eq!(
        proxy.backend_port, 8080,
        "ClusterIP DNS must keep the Service port so kube-proxy can DNAT onto targetPort"
    );
}

#[test]
fn headless_ready_endpoint_slices_still_expand_to_pod_ip_and_target_port() {
    let result = translate_k8s_objects(
        &[
            headless_service("headless-manual-endpointslices", json!(3000)),
            ready_manual_slice("headless-manual-endpointslices", "10.244.0.21"),
            http_route(
                "/headless-manual-endpointslices",
                "headless-manual-endpointslices",
            ),
        ],
        options(),
    )
    .expect("headless Service with ready EndpointSlices should expand");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(proxy.backend_host, "10.244.0.21");
    assert_eq!(proxy.backend_port, 3000);
}

#[test]
fn external_name_without_cluster_ip_keeps_service_port() {
    let result = translate_k8s_objects(
        &[
            service(
                "external-backend",
                json!({
                    "type": "ExternalName",
                    "externalName": "example.com",
                    "ports": [{
                        "name": "first-port",
                        "protocol": "TCP",
                        "port": 8080,
                        "targetPort": 3000
                    }]
                }),
            ),
            empty_manual_slice("external-backend"),
            http_route("/external", "external-backend"),
        ],
        options(),
    )
    .expect("ExternalName Service without ClusterIP should translate");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(
        proxy.backend_host,
        "external-backend.default.svc.cluster.local"
    );
    assert_eq!(
        proxy.backend_port, 8080,
        "ExternalName DNS fallback must keep the declared Service port, not targetPort"
    );
}

#[test]
fn headless_cluster_ips_none_sentinel_dials_target_port() {
    let result = translate_k8s_objects(
        &[
            service(
                "headless-cluster-ips",
                json!({
                    "clusterIPs": ["None"],
                    "ports": [{
                        "name": "first-port",
                        "protocol": "TCP",
                        "port": 8080,
                        "targetPort": 3000
                    }]
                }),
            ),
            empty_manual_slice("headless-cluster-ips"),
            http_route("/headless-cluster-ips", "headless-cluster-ips"),
        ],
        options(),
    )
    .expect("headless clusterIPs sentinel should translate");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(
        proxy.backend_host,
        "headless-cluster-ips.default.svc.cluster.local"
    );
    assert_eq!(proxy.backend_port, 3000);
}

#[test]
fn conflicting_headless_sentinel_and_vip_keeps_service_port() {
    let result = translate_k8s_objects(
        &[
            service(
                "conflicting-cluster-ips",
                json!({
                    "clusterIPs": ["None", "10.96.44.110"],
                    "ports": [{
                        "name": "first-port",
                        "protocol": "TCP",
                        "port": 8080,
                        "targetPort": 3000
                    }]
                }),
            ),
            empty_manual_slice("conflicting-cluster-ips"),
            http_route("/conflicting-cluster-ips", "conflicting-cluster-ips"),
        ],
        options(),
    )
    .expect("malformed mixed clusterIPs should translate conservatively");

    assert_eq!(result.config.proxies.len(), 1);
    assert_eq!(
        result.config.proxies[0].backend_port, 8080,
        "a mixed headless sentinel and real VIP must not select targetPort"
    );
}

#[test]
fn headless_named_target_port_resolves_from_empty_slice_ports() {
    let mut slice = empty_manual_slice("headless-named");
    slice.spec["ports"] = json!([{
        "name": "app-http",
        "port": 3001,
        "protocol": "TCP"
    }]);
    let result = translate_k8s_objects(
        &[
            headless_service("headless-named", json!("app-http")),
            slice,
            http_route("/named", "headless-named"),
        ],
        options(),
    )
    .expect("named targetPort should resolve from EndpointSlice ports without ready addresses");

    assert_eq!(result.config.proxies.len(), 1);
    let proxy = &result.config.proxies[0];
    assert_eq!(
        proxy.backend_host,
        "headless-named.default.svc.cluster.local"
    );
    assert_eq!(proxy.backend_port, 3001);
}

#[test]
fn endpoint_slice_ports_override_numeric_targets_without_changing_silent_slice_fallback() {
    let cases = [
        (
            "absent",
            None,
            json!([{"name": "first-port", "port": 3000}]),
            3000,
        ),
        (
            "named",
            Some(json!("app-http")),
            json!([{"name": "app-http", "port": 3000}]),
            3000,
        ),
        (
            "named-service-port",
            Some(json!("app-http")),
            json!([{"name": "first-port", "port": 3000}]),
            3000,
        ),
        (
            "service-name-before-target-name",
            Some(json!("app-http")),
            json!([{"name": "app-http", "port": 4000}, {"name": "first-port", "port": 3000}]),
            3000,
        ),
        (
            "matching",
            Some(json!(3000)),
            json!([{"name": "first-port", "port": 3000}]),
            3000,
        ),
        (
            "defaulted",
            Some(json!(8080)),
            json!([{"name": "first-port", "port": 3000}]),
            3000,
        ),
        (
            "explicit-different",
            Some(json!(9000)),
            json!([{"name": "first-port", "port": 3000}]),
            3000,
        ),
        (
            "unmatched",
            Some(json!(9000)),
            json!([{"name": "other", "port": 3000}]),
            9000,
        ),
        ("silent", Some(json!(9000)), json!([]), 9000),
        (
            "multiple",
            Some(json!(8080)),
            json!([{"name": "other", "port": 4000}, {"name": "first-port", "port": 3000}]),
            3000,
        ),
    ];
    for cluster_ip in ["10.96.0.10", "None"] {
        for (name, target, ports, expected) in &cases {
            let mut service = headless_service("backend", json!(8080));
            service.spec["clusterIP"] = json!(cluster_ip);
            if let Some(target) = target {
                service.spec["ports"][0]["targetPort"] = target.clone();
            } else {
                service.spec["ports"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("targetPort");
            }
            let mut slice = ready_manual_slice("backend", "10.1.0.10");
            slice.spec["ports"] = ports.clone();
            let translated = translate_k8s_objects(
                &[service, slice, http_route("/slice", "backend")],
                options(),
            )
            .expect("translate endpoint port matrix");
            assert_eq!(translated.config.proxies.len(), 1, "{cluster_ip}/{name}");
            let proxy = &translated.config.proxies[0];
            assert_eq!(proxy.backend_host, "10.1.0.10", "{cluster_ip}/{name}");
            assert_eq!(proxy.backend_port, *expected, "{cluster_ip}/{name}");
        }
    }
}

#[test]
fn unnamed_numeric_target_uses_only_an_unambiguous_unnamed_slice_port() {
    for (ports, expected) in [
        (json!([{"port": 3000}]), 3000),
        (json!([{"name": "unrelated", "port": 3000}]), 8080),
        (json!([{"port": 3000}, {"port": 4000}]), 8080),
    ] {
        let mut service = headless_service("backend", json!(8080));
        service.spec["ports"][0]
            .as_object_mut()
            .unwrap()
            .remove("name");
        let mut slice = ready_manual_slice("backend", "10.1.0.10");
        slice.spec["ports"] = ports;
        let translated = translate_k8s_objects(
            &[service, slice, http_route("/slice", "backend")],
            options(),
        )
        .expect("translate unnamed endpoint port");
        assert_eq!(translated.config.proxies[0].backend_port, expected);
    }
}

#[test]
fn selector_based_cluster_ip_keeps_service_dns_and_port() {
    let mut service = headless_service("backend", json!(8080));
    service.spec["clusterIP"] = json!("10.96.0.10");
    service.spec["selector"] = json!({"app": "backend"});
    let slice = ready_manual_slice("backend", "10.1.0.10");
    let translated = translate_k8s_objects(
        &[service, slice, http_route("/slice", "backend")],
        options(),
    )
    .expect("translate selector Service");
    assert_eq!(
        translated.config.proxies[0].backend_host,
        "backend.default.svc.cluster.local"
    );
    assert_eq!(translated.config.proxies[0].backend_port, 8080);
}

#[test]
fn selector_based_headless_service_and_empty_slice_use_the_matching_slice_port() {
    for ready in [false, true] {
        let mut service = headless_service("backend", json!(8080));
        service.spec["selector"] = json!({"app": "backend"});
        let slice = if ready {
            ready_manual_slice("backend", "10.1.0.10")
        } else {
            empty_manual_slice("backend")
        };
        let translated = translate_k8s_objects(
            &[service, slice, http_route("/slice", "backend")],
            options(),
        )
        .expect("translate headless selector Service");
        assert_eq!(translated.config.proxies[0].backend_port, 3000);
        assert_eq!(
            translated.config.proxies[0].backend_host,
            if ready {
                "10.1.0.10"
            } else {
                "backend.default.svc.cluster.local"
            }
        );
    }
}

#[test]
fn unnamed_service_without_target_port_uses_the_unnamed_slice_port() {
    let mut service = headless_service("backend", json!(8080));
    let port = service.spec["ports"][0].as_object_mut().unwrap();
    port.remove("name");
    port.remove("targetPort");
    let mut slice = ready_manual_slice("backend", "10.1.0.10");
    slice.spec["ports"] = json!([{"port": 3000}]);
    let translated = translate_k8s_objects(
        &[service, slice, http_route("/slice", "backend")],
        options(),
    )
    .expect("translate unnamed default Service port");
    assert_eq!(translated.config.proxies[0].backend_host, "10.1.0.10");
    assert_eq!(translated.config.proxies[0].backend_port, 3000);
}
