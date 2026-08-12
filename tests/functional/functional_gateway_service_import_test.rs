//! Live request-path coverage for Gateway API MCS `ServiceImport` backendRefs
//! (issue #3270).
//!
//! The unit/integration suites prove translation and status parity. This suite
//! starts the real gateway from that translated document and proves both the
//! admitted TCP path and the fail-closed unsupported-protocol path on the wire.

use std::time::Duration;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};

use crate::common::{TestGateway, ephemeral_port, spawn_http_identifying};

const NAMESPACE: &str = "default";
const ROUTE_HOST: &str = "store.example.test";

fn object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{kind}-{name}"),
            namespace: NAMESPACE.to_string(),
            generation: Some(1),
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: Some("2024-01-01T00:00:00Z".to_string()),
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(Default::default()),
    }
}

fn service_import_snapshot(
    backend_port: u16,
    listener_port: u16,
    protocol: &str,
) -> Vec<K8sObject> {
    let mut gateway_class = object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": "ferrum.io/gateway-controller" }),
    );
    gateway_class.metadata.namespace.clear();

    let mut endpoint_slice = object(
        "discovery.k8s.io/v1",
        "EndpointSlice",
        "store-mcs",
        json!({
            "ports": [{ "port": backend_port }],
            "endpoints": [{
                "addresses": ["127.0.0.1"],
                "conditions": { "ready": true }
            }]
        }),
    );
    endpoint_slice.metadata.labels.insert(
        "multicluster.kubernetes.io/service-name".to_string(),
        "store".to_string(),
    );

    vec![
        gateway_class,
        object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": listener_port,
                    "protocol": "HTTP",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }]
            }),
        ),
        object(
            "multicluster.x-k8s.io/v1alpha1",
            "ServiceImport",
            "store",
            json!({
                "type": "ClusterSetIP",
                "ports": [{ "port": backend_port, "protocol": protocol }]
            }),
        ),
        endpoint_slice,
        object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "store-route",
            json!({
                "parentRefs": [{ "name": "edge" }],
                "hostnames": [ROUTE_HOST],
                "rules": [{
                    "matches": [{
                        "path": { "type": "PathPrefix", "value": "/mcs" }
                    }],
                    "backendRefs": [{
                        "group": "multicluster.x-k8s.io",
                        "kind": "ServiceImport",
                        "name": "store",
                        "port": backend_port
                    }]
                }]
            }),
        ),
    ]
}

fn translated_config_yaml(backend_port: u16, listener_port: u16, protocol: &str) -> String {
    let options = K8sTranslationOptions::new(
        NAMESPACE.to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_pod_discovery_enabled(true);
    let translated = translate_k8s_objects(
        &service_import_snapshot(backend_port, listener_port, protocol),
        options,
    )
    .expect("ServiceImport snapshot should translate");

    if protocol == "TCP" {
        assert_eq!(translated.config.proxies[0].backend_host, "127.0.0.1");
        assert_eq!(translated.config.proxies[0].backend_port, backend_port);
    } else {
        let dispatch = translated
            .config
            .plugin_configs
            .iter()
            .find(|plugin| plugin.plugin_name == "mesh_route_dispatch")
            .expect("unsupported protocol must materialize a fail-closed dispatch");
        assert_eq!(
            dispatch.config["rules"][0]["fault"]["abort"]["status_code"],
            500
        );
    }

    serde_yaml::to_string(&json!({
        "version": "1",
        "proxies": translated.config.proxies,
        "consumers": translated.config.consumers,
        "plugin_configs": translated.config.plugin_configs,
        "upstreams": translated.config.upstreams,
    }))
    .expect("serialize translated gateway config")
}

async fn start_gateway(backend_port: u16, protocol: &str) -> TestGateway {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_error = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let listener_port = ephemeral_port().await.expect("reserve listener port");
        let builder = TestGateway::builder()
            // This suite exercises ServiceImport routing, not Service-port
            // remapping. Use the exact process-global frontend port so an
            // unrelated parallel :80 listener cannot create a bind refusal.
            .mode_file(translated_config_yaml(
                backend_port,
                listener_port,
                protocol,
            ))
            .namespace(NAMESPACE)
            .log_level("warn")
            .reserve_listener_port(backend_port)
            .max_attempts(1)
            .capture_output()
            .env("FERRUM_PROXY_HTTP_PORT", listener_port.to_string());
        match builder.spawn_classified().await {
            Ok(gateway) => return gateway,
            Err(failure) if failure.listener_addr_in_use => {
                last_error = failure.detail;
                eprintln!(
                    "gateway spawn attempt {attempt} lost an ephemeral-port race; retrying: \
                     {last_error}"
                );
            }
            Err(failure) => panic!(
                "ServiceImport gateway failed for a deterministic reason on attempt {attempt}: {}",
                failure.detail
            ),
        }
    }
    panic!("ServiceImport gateway failed after {MAX_ATTEMPTS} port races: {last_error}");
}

async fn request(gateway: &TestGateway) -> reqwest::Response {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("HTTP client")
        .get(gateway.proxy_url("/mcs/live"))
        .header(reqwest::header::HOST, ROUTE_HOST)
        .send()
        .await
        .expect("gateway must answer the live request")
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_import_tcp_reaches_backend_and_udp_fails_closed() {
    let backend = spawn_http_identifying("service-import-live")
        .await
        .expect("spawn ServiceImport backend");

    let admitted = start_gateway(backend.port, "TCP").await;
    let response = request(&admitted).await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.expect("admitted response body");
    assert!(
        body.contains("service-import-live"),
        "the real MCS-selected backend must answer: {body}"
    );
    drop(admitted);

    let rejected = start_gateway(backend.port, "UDP").await;
    let response = request(&rejected).await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "a UDP ServiceImport must be rejected by the gateway, not dialed as HTTP"
    );
}
