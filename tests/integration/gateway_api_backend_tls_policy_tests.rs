//! Integration coverage for Gateway API `BackendTLSPolicy` translation onto
//! Service-backed HTTPRoute backends (issue #3276).
//!
//! Pins watch/index → route materialization: HTTPS scheme, upstream SNI/CA/SAN
//! projection, System well-known roots, invalid CA fail-closed, and policy
//! withdrawal on delete from the translated snapshot.

use crate::scaffolding::port_registry::TestSocket;

use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{BackendScheme, GatewayConfig, Upstream};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::health_check::HealthChecker;
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::status::{
    FERRUM_GATEWAY_CONTROLLER_NAME, GatewayApiStatusUpdate, plan_gateway_api_status_updates,
};
use ferrum_edge::tls::source::SYSTEM_TRUST_ROOTS_SOURCE;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: match kind {
            "Secret" | "ConfigMap" | "Service" => "v1".to_string(),
            "BackendTLSPolicy" => "gateway.networking.k8s.io/v1".to_string(),
            _ => "gateway.networking.k8s.io/v1".to_string(),
        },
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: Default::default(),
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn gateway_class() -> K8sObject {
    let mut gc = object(
        "GatewayClass",
        "ferrum",
        serde_json::json!({
            "controllerName": "ferrum.io/gateway-controller"
        }),
    );
    gc.metadata.namespace.clear();
    gc
}

fn gateway() -> K8sObject {
    object(
        "Gateway",
        "edge",
        serde_json::json!({
            "gatewayClassName": "ferrum",
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "namespaces": { "from": "Same" } }
            }]
        }),
    )
}

fn service(name: &str, port: u16, port_name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [{
                "name": port_name,
                "port": port,
                "targetPort": port
            }]
        }),
    )
}

fn http_route(name: &str, service_name: &str, port: u16) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        serde_json::json!({
            "parentRefs": [{ "name": "edge" }],
            "hostnames": ["app.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                "backendRefs": [{
                    "name": service_name,
                    "port": port
                }]
            }]
        }),
    )
}

fn ca_configmap(name: &str) -> K8sObject {
    let pem = include_str!("../certs/server.crt");
    object(
        "ConfigMap",
        name,
        serde_json::json!({
            "data": {
                "ca.crt": pem
            }
        }),
    )
}

fn ca_secret(name: &str) -> K8sObject {
    use base64::Engine as _;
    let pem = include_str!("../certs/server.crt");
    object(
        "Secret",
        name,
        serde_json::json!({
            "type": "Opaque",
            "data": {
                "ca.crt": base64::engine::general_purpose::STANDARD.encode(pem)
            }
        }),
    )
}

fn backend_tls_policy_system(name: &str, service_name: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "backend.example.com",
                "wellKnownCACertificates": "System"
            }
        }),
    )
}

fn backend_tls_policy_configmap(
    name: &str,
    service_name: &str,
    configmap_name: &str,
    sans: &[(&str, &str)],
) -> K8sObject {
    let subject_alt_names: Vec<serde_json::Value> = sans
        .iter()
        .map(|(san_type, value)| match *san_type {
            "Hostname" => serde_json::json!({ "type": "Hostname", "hostname": value }),
            "URI" => serde_json::json!({ "type": "URI", "uri": value }),
            _ => panic!("unsupported SAN type in test fixture"),
        })
        .collect();
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "auth.example.com",
                "caCertificateRefs": [{
                    "group": "",
                    "kind": "ConfigMap",
                    "name": configmap_name
                }],
                "subjectAltNames": subject_alt_names
            }
        }),
    )
}

fn backend_tls_policy_secret(name: &str, service_name: &str, secret_name: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "secret-backend.example.com",
                "caCertificateRefs": [{
                    "group": "",
                    "kind": "Secret",
                    "name": secret_name
                }]
            }
        }),
    )
}

fn backend_tls_policy_missing_ca(name: &str, service_name: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name
            }],
            "validation": {
                "hostname": "broken.example.com",
                "caCertificateRefs": [{
                    "group": "",
                    "kind": "ConfigMap",
                    "name": "missing-ca"
                }]
            }
        }),
    )
}

#[test]
fn backend_tls_policy_system_enables_https_sni_on_upstream() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.len() == 1,
        "BackendTLSPolicy should promote the single backend onto an Upstream for SNI: {:?}",
        translated.config.upstreams
    );
    let upstream = &translated.config.upstreams[0];
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("backend.example.com")
    );
    assert!(upstream.backend_tls_verify_server_cert);
    // `wellKnownCACertificates: System` must project the explicit system-roots
    // source, NOT an unset CA path: unset falls back to the cluster-global
    // FERRUM_TLS_CA_BUNDLE_PATH, so a private cluster CA would silently replace
    // the public roots the policy asked for.
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some(SYSTEM_TRUST_ROOTS_SOURCE)
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https)
                && proxy.upstream_id.as_deref() == Some(upstream.id.as_str())),
        "HTTPRoute proxy must use HTTPS against the TLS-backed upstream"
    );
}

#[test]
fn backend_tls_policy_configmap_ca_and_sans_project_to_upstream() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("auth", 8443, "https"),
        ca_configmap("auth-cert"),
        http_route("auth-route", "auth", 8443),
        backend_tls_policy_configmap(
            "auth-tls",
            "auth",
            "auth-cert",
            &[
                ("Hostname", "auth.example.com"),
                ("URI", "spiffe://cluster.local/ns/default/sa/auth"),
            ],
        ),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("auth.example.com")
    );
    let ca = upstream
        .backend_tls_server_ca_cert_path
        .as_deref()
        .expect("ConfigMap CA should be projected as inline PEM");
    assert!(
        ca.contains("BEGIN CERTIFICATE"),
        "expected inline PEM CA, got {ca}"
    );
    assert_eq!(
        upstream.backend_tls_san_allow_list,
        vec![
            "auth.example.com".to_string(),
            "spiffe://cluster.local/ns/default/sa/auth".to_string(),
        ]
    );
}

#[test]
fn backend_tls_policy_secret_ca_uses_k8s_uri() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("payments", 8443, "https"),
        ca_secret("payments-ca"),
        http_route("payments-route", "payments", 8443),
        backend_tls_policy_secret("payments-tls", "payments", "payments-ca"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected upstream");
    let ca = upstream
        .backend_tls_server_ca_cert_path
        .as_deref()
        .expect("Secret CA should project a k8s:// URI");
    assert!(
        ca.starts_with("k8s://default/payments-ca#ca.crt?sha256="),
        "unexpected CA URI {ca}"
    );
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secret-backend.example.com")
    );
}

#[test]
fn backend_tls_policy_missing_ca_fails_closed_with_fault_route() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("broken", 8080, "http"),
        http_route("broken-route", "broken", 8080),
        backend_tls_policy_missing_ca("broken-tls", "broken"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "invalid BackendTLSPolicy must not create a TLS upstream"
    );
    assert!(
        translated
            .warnings
            .iter()
            .any(|warning| { warning.contains("BackendTLSPolicy") && warning.contains("invalid") }),
        "expected invalid-policy warning, got {:?}",
        translated.warnings
    );
    let proxy = translated
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some("/api"))
        .expect("fail-closed route should still capture traffic");
    let has_fault_plugin = translated.config.plugin_configs.iter().any(|plugin| {
        plugin.namespace == proxy.namespace
            && plugin.plugin_name == "mesh_route_dispatch"
            && plugin
                .config
                .get("rules")
                .and_then(|rules| rules.as_array())
                .into_iter()
                .flatten()
                .any(|rule| {
                    rule.get("fault")
                        .and_then(|fault| fault.get("abort"))
                        .and_then(|abort| abort.get("body"))
                        .and_then(|body| body.as_str())
                        .is_some_and(|body| body.contains("BackendTLSPolicy"))
                })
    });
    assert!(
        has_fault_plugin,
        "invalid BackendTLSPolicy should materialize an HTTP 500 fault abort"
    );
}

#[test]
fn backend_tls_policy_delete_withdraws_tls_overlay() {
    let with_policy = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let active = translate_k8s_objects(&with_policy, options()).expect("translate with policy");
    assert_eq!(active.config.upstreams.len(), 1);
    assert!(
        active
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https))
    );

    let without_policy = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
    ];
    let withdrawn =
        translate_k8s_objects(&without_policy, options()).expect("translate without policy");
    assert!(
        withdrawn.config.upstreams.is_empty(),
        "removing BackendTLSPolicy should restore the direct-backend HTTPRoute shape"
    );
    assert!(
        withdrawn
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)
                && proxy.upstream_id.is_none()),
        "withdrawn policy must leave plaintext direct backends"
    );
}

// ---------------------------------------------------------------------------
// Mixed policy-covered / uncovered backend sets (fail closed)
// ---------------------------------------------------------------------------

fn split_http_route(name: &str, backends: &[(&str, u16, u32)]) -> K8sObject {
    let backend_refs: Vec<serde_json::Value> = backends
        .iter()
        .map(|(service, port, weight)| {
            serde_json::json!({ "name": service, "port": port, "weight": weight })
        })
        .collect();
    object(
        "HTTPRoute",
        name,
        serde_json::json!({
            "parentRefs": [{ "name": "edge" }],
            "hostnames": ["split.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": "/split" } }],
                "backendRefs": backend_refs
            }]
        }),
    )
}

fn fault_body_mentions(translated: &ferrum_edge::config_sources::k8s::K8sTranslation) -> bool {
    translated.config.plugin_configs.iter().any(|plugin| {
        plugin.plugin_name == "mesh_route_dispatch"
            && plugin
                .config
                .get("rules")
                .and_then(|rules| rules.as_array())
                .into_iter()
                .flatten()
                .any(|rule| {
                    // `mesh_route_dispatch`'s `FaultAbortConfig` spells this
                    // `status_code` and is `deny_unknown_fields`; matching on
                    // `status` would never fire and would make every
                    // fail-closed assertion below vacuous.
                    rule.get("fault")
                        .and_then(|fault| fault.get("abort"))
                        .and_then(|abort| abort.get("status_code"))
                        .and_then(serde_json::Value::as_u64)
                        == Some(500)
                        && rule
                            .get("fault")
                            .and_then(|fault| fault.get("abort"))
                            .and_then(|abort| abort.get("body"))
                            .and_then(|body| body.as_str())
                            .is_some_and(|body| body.contains("BackendTLSPolicy"))
                })
    })
}

#[test]
fn backend_tls_policy_mixed_covered_and_uncovered_backends_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        service("ratings", 8080, "http"),
        split_http_route("split-route", &[("reviews", 8080, 1), ("ratings", 8080, 1)]),
        // Only `reviews` is covered. `ratings` has no policy at all.
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");

    assert!(
        translated.config.upstreams.is_empty(),
        "a partially covered backend set must not materialize a TLS upstream: {:?}",
        translated.config.upstreams
    );
    assert!(
        !translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https)),
        "the uncovered Service must never be promoted to HTTPS"
    );
    let warning = translated
        .warnings
        .iter()
        .find(|warning| warning.contains("mixes BackendTLSPolicy-covered and uncovered backends"))
        .unwrap_or_else(|| {
            panic!(
                "expected a field-specific mixed-coverage warning, got {:?}",
                translated.warnings
            )
        });
    assert!(
        warning.contains("spec.rules[].backendRefs"),
        "warning must name the offending field: {warning}"
    );
    assert!(
        warning.contains("Service default/reviews") && warning.contains("Service default/ratings"),
        "warning must identify both sides: {warning}"
    );
    assert!(
        fault_body_mentions(&translated),
        "mixed coverage must materialize an HTTP 500 fault abort"
    );
}

#[test]
fn backend_tls_policy_covering_every_backend_still_applies() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        service("ratings", 8080, "http"),
        split_http_route("split-route", &[("reviews", 8080, 1), ("ratings", 8080, 1)]),
        backend_tls_policy_system("reviews-tls", "reviews"),
        // Byte-identical validation, so both overlays compare equal and the
        // combined upstream carries one unambiguous TLS identity.
        backend_tls_policy_system("ratings-tls", "ratings"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("uniformly covered backends should materialize one TLS upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("backend.example.com")
    );
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some(SYSTEM_TRUST_ROOTS_SOURCE)
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Https))
    );
}

#[test]
fn backend_tls_policy_zero_weight_uncovered_backend_does_not_fail_closed() {
    // A zero-weight backendRef receives no traffic, so it is not part of the
    // effective backend set and must not trip the mixed-coverage guard.
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        service("ratings", 8080, "http"),
        split_http_route("split-route", &[("reviews", 8080, 1), ("ratings", 8080, 0)]),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        !translated
            .warnings
            .iter()
            .any(|warning| warning.contains("mixes BackendTLSPolicy-covered")),
        "zero-weight backends must not trip the mixed-coverage guard: {:?}",
        translated.warnings
    );
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected a TLS upstream for the only traffic-bearing backend");
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some(SYSTEM_TRUST_ROOTS_SOURCE)
    );
}

// ---------------------------------------------------------------------------
// targetRefs[].sectionName resolution
// ---------------------------------------------------------------------------

fn multi_port_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "http", "port": 8080, "targetPort": 8080 },
                { "name": "https", "port": 8443, "targetPort": 8443 }
            ]
        }),
    )
}

fn sectioned_policy(name: &str, service_name: &str, section: &str, hostname: &str) -> K8sObject {
    object(
        "BackendTLSPolicy",
        name,
        serde_json::json!({
            "targetRefs": [{
                "group": "",
                "kind": "Service",
                "name": service_name,
                "sectionName": section
            }],
            "validation": {
                "hostname": hostname,
                "wellKnownCACertificates": "System"
            }
        }),
    )
}

#[test]
fn backend_tls_policy_section_name_matches_only_its_service_port() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-tls", "api", "https", "secure.example.com"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("sectionName-matched policy should apply");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secure.example.com")
    );
}

#[test]
fn backend_tls_policy_section_name_mismatch_leaves_backend_plaintext() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        // Route targets the `http` (8080) port; the policy is scoped to `https`.
        http_route("api-route", "api", 8080),
        sectioned_policy("api-tls", "api", "https", "secure.example.com"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "a sectionName-scoped policy must not apply to a different Service port"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)),
        "the unmatched port must stay plaintext"
    );
}

#[test]
fn backend_tls_policy_section_scoped_wins_over_unscoped_for_its_port() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-tls-https", "api", "https", "secure.example.com"),
        backend_tls_policy_system("api-tls-any", "api"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("expected an upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secure.example.com"),
        "the port-scoped policy must win over the Service-wide one"
    );
}

// ---------------------------------------------------------------------------
// status.ancestors
// ---------------------------------------------------------------------------

fn policy_status_update(objects: &[K8sObject], name: &str) -> Option<GatewayApiStatusUpdate> {
    let translated = translate_k8s_objects(objects, options()).expect("translate");
    plan_gateway_api_status_updates(objects, options(), &translated.route_conflicts)
        .into_iter()
        .find(|update| update.kind == "BackendTLSPolicy" && update.name == name)
}

fn ferrum_ancestors(update: &GatewayApiStatusUpdate) -> Vec<Value> {
    update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .expect("status.ancestors must be written")
        .iter()
        .filter(|ancestor| {
            ancestor.get("controllerName").and_then(Value::as_str)
                == Some(FERRUM_GATEWAY_CONTROLLER_NAME)
        })
        .cloned()
        .collect()
}

fn condition<'a>(ancestor: &'a Value, condition_type: &str) -> &'a Value {
    ancestor
        .get("conditions")
        .and_then(Value::as_array)
        .expect("conditions")
        .iter()
        .find(|condition| condition.get("type").and_then(Value::as_str) == Some(condition_type))
        .unwrap_or_else(|| panic!("missing {condition_type} condition in {ancestor}"))
}

/// The one ancestorRef Ferrum ever writes for a `BackendTLSPolicy`.
fn service_ancestor_ref(name: &str) -> Value {
    serde_json::json!({
        "group": "",
        "kind": "Service",
        "namespace": "default",
        "name": name
    })
}

/// `n` ancestors owned by other controllers, each with a distinct ancestorRef
/// so the CRD's list-map key is unique.
fn third_party_ancestors(n: usize) -> Value {
    Value::Array(
        (0..n)
            .map(|index| {
                serde_json::json!({
                    "ancestorRef": {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "namespace": "default",
                        "name": format!("other-{index:02}")
                    },
                    "controllerName": "example.com/other-controller",
                    "conditions": [{
                        "type": "Accepted",
                        "status": "True",
                        "reason": "Accepted",
                        "message": "another controller's verdict",
                        "lastTransitionTime": "2020-01-01T00:00:00Z"
                    }]
                })
            })
            .collect(),
    )
}

#[test]
fn backend_tls_policy_status_reports_accepted_service_ancestor() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    assert_eq!(update.api_version, "gateway.networking.k8s.io/v1");
    assert_eq!(update.namespace, "default");

    let ancestors = ferrum_ancestors(&update);
    assert_eq!(
        ancestors.len(),
        1,
        "the targeted Service is Ferrum's only ancestor"
    );
    let ancestor = &ancestors[0];
    assert_eq!(
        ancestor.get("ancestorRef"),
        Some(&service_ancestor_ref("reviews"))
    );
    let accepted = condition(ancestor, "Accepted");
    assert_eq!(accepted.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Accepted")
    );
    let resolved = condition(ancestor, "ResolvedRefs");
    assert_eq!(resolved.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        resolved.get("reason").and_then(Value::as_str),
        Some("ResolvedRefs")
    );
}

#[test]
fn backend_tls_policy_status_reports_invalid_ca_certificate_ref() {
    let objects = vec![
        gateway_class(),
        gateway(),
        service("broken", 8080, "http"),
        http_route("broken-route", "broken", 8080),
        backend_tls_policy_missing_ca("broken-tls", "broken"),
    ];
    let update = policy_status_update(&objects, "broken-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    assert_eq!(ancestors.len(), 1);
    let ancestor = &ancestors[0];

    let accepted = condition(ancestor, "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("NoValidCACertificate")
    );
    let resolved = condition(ancestor, "ResolvedRefs");
    assert_eq!(
        resolved.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        resolved.get("reason").and_then(Value::as_str),
        Some("InvalidCACertificateRef"),
        "a missing ConfigMap CA is a reference failure, not a body failure"
    );
    let message = resolved
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("caCertificateRefs[0]") && message.contains("default/missing-ca"),
        "message must be field-specific: {message}"
    );
}

#[test]
fn backend_tls_policy_status_marks_precedence_loser_conflicted() {
    let mut older = backend_tls_policy_system("a-older", "reviews");
    older.metadata.creation_timestamp = Some("2026-01-01T00:00:00Z".to_string());
    older.spec["validation"]["hostname"] = serde_json::json!("older.example.com");
    let mut newer = backend_tls_policy_system("b-newer", "reviews");
    newer.metadata.creation_timestamp = Some("2026-01-02T00:00:00Z".to_string());
    newer.spec["validation"]["hostname"] = serde_json::json!("newer.example.com");
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        newer,
        older,
    ];

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("the precedence winner must still materialize TLS");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("older.example.com"),
        "runtime and status must use the same oldest-policy winner"
    );

    let newer_update = policy_status_update(&objects, "b-newer").expect("loser status update");
    let newer_ancestors = ferrum_ancestors(&newer_update);
    let accepted = condition(&newer_ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Conflicted")
    );

    let older_update = policy_status_update(&objects, "a-older").expect("winner status update");
    let older_ancestors = ferrum_ancestors(&older_update);
    assert_eq!(
        condition(&older_ancestors[0], "Accepted")
            .get("status")
            .and_then(Value::as_str),
        Some("True")
    );
}

#[test]
fn backend_tls_policy_status_marks_fully_shadowed_service_policy_conflicted() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-http", "api", "http", "http.example.com"),
        sectioned_policy("api-https", "api", "https", "https.example.com"),
        backend_tls_policy_system("api-any", "api"),
    ];

    let wildcard = policy_status_update(&objects, "api-any").expect("wildcard status update");
    let wildcard_ancestors = ferrum_ancestors(&wildcard);
    let accepted = condition(&wildcard_ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Conflicted"),
        "a Service-wide policy that loses every eligible port governs nothing"
    );

    for winner in ["api-http", "api-https"] {
        let update = policy_status_update(&objects, winner).expect("section status update");
        let ancestors = ferrum_ancestors(&update);
        assert_eq!(
            condition(&ancestors[0], "Accepted")
                .get("status")
                .and_then(Value::as_str),
            Some("True"),
            "the section-specific winner {winner} must stay accepted"
        );
    }
}

#[test]
fn backend_tls_policy_status_keeps_partially_effective_service_policy_accepted() {
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-https", "api", "https", "https.example.com"),
        backend_tls_policy_system("api-any", "api"),
    ];

    let wildcard = policy_status_update(&objects, "api-any").expect("wildcard status update");
    let wildcard_ancestors = ferrum_ancestors(&wildcard);
    assert_eq!(
        condition(&wildcard_ancestors[0], "Accepted")
            .get("status")
            .and_then(Value::as_str),
        Some("True"),
        "the Service-wide policy still governs the unclaimed http port"
    );
}

#[test]
fn backend_tls_policy_status_reports_invalid_target_reference_kind() {
    let mut policy = backend_tls_policy_system("bad-target", "reviews");
    policy.spec["targetRefs"][0]["kind"] = serde_json::json!("Deployment");
    let translated = translate_k8s_objects(&[policy], options()).expect("translate");
    let status = translated
        .backend_tls_policy_statuses
        .first()
        .expect("policy status projection");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert!(!status.resolved_refs);
    assert_eq!(status.resolved_refs_reason, "InvalidKind");
}

#[test]
fn backend_tls_policy_status_reports_cross_namespace_target_as_ref_not_permitted() {
    let mut policy = backend_tls_policy_system("cross-ns-target", "reviews");
    policy.spec["targetRefs"][0]["namespace"] = serde_json::json!("other");
    let translated = translate_k8s_objects(&[policy], options()).expect("translate");
    let status = translated
        .backend_tls_policy_statuses
        .first()
        .expect("policy status projection");
    assert!(!status.accepted);
    assert_eq!(status.accepted_reason, "Invalid");
    assert!(!status.resolved_refs);
    assert_eq!(status.resolved_refs_reason, "RefNotPermitted");
}

#[test]
fn backend_tls_policy_rejects_unrepresentable_or_malformed_optional_shapes() {
    let cases = [
        (
            "multiple-targets",
            serde_json::json!({
                "targetRefs": [
                    {"group": "", "kind": "Service", "name": "reviews"},
                    {"group": "", "kind": "Service", "name": "ratings"}
                ],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System"
                }
            }),
            "exactly one entry",
        ),
        (
            "empty-section",
            serde_json::json!({
                "targetRefs": [{
                    "group": "", "kind": "Service", "name": "reviews", "sectionName": ""
                }],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System"
                }
            }),
            "sectionName must not be empty",
        ),
        (
            "malformed-sans",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "reviews"}],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System",
                    "subjectAltNames": {"type": "Hostname", "hostname": "backend.example.com"}
                }
            }),
            "subjectAltNames must be an array",
        ),
        (
            "unsupported-options",
            serde_json::json!({
                "targetRefs": [{"group": "", "kind": "Service", "name": "reviews"}],
                "validation": {
                    "hostname": "backend.example.com",
                    "wellKnownCACertificates": "System"
                },
                "options": {"example.com/min-version": "TLS1.3"}
            }),
            "spec.options is not supported",
        ),
    ];

    for (name, spec, diagnostic) in cases {
        let objects = vec![
            gateway_class(),
            gateway(),
            service("reviews", 8080, "http"),
            service("ratings", 8080, "http"),
            http_route("reviews-route", "reviews", 8080),
            object("BackendTLSPolicy", name, spec),
        ];
        let translated = translate_k8s_objects(&objects, options()).expect("translate");
        assert!(
            translated
                .warnings
                .iter()
                .any(|warning| warning.contains(diagnostic)),
            "{name} must fail with a field-specific diagnostic: {:?}",
            translated.warnings
        );
        assert!(
            fault_body_mentions(&translated),
            "{name} must retain the affected route as a fail-closed HTTP 500 rather than silently broadening to plaintext"
        );
    }
}

/// Seventeen managed Gateways routing to the targeted Service used to derive
/// seventeen ancestors, be truncated to the CRD's MaxItems=16, and keep
/// applying the policy through the Gateway that fell off the list. Ferrum's
/// ancestor is the Service, so the Gateway count is irrelevant: one entry, no
/// truncation, and the policy stays uniformly in effect.
#[test]
fn backend_tls_policy_status_is_one_service_ancestor_regardless_of_gateway_count() {
    let mut objects = vec![gateway_class(), service("reviews", 8080, "http")];
    for index in 0..17 {
        let gateway_name = format!("edge-{index:02}");
        let mut gateway = gateway();
        gateway.metadata.name = gateway_name.clone();
        let mut route = http_route(&format!("route-{index:02}"), "reviews", 8080);
        route.spec["parentRefs"][0]["name"] = serde_json::json!(gateway_name);
        route.spec["hostnames"][0] = serde_json::json!(format!("reviews-{index:02}.example.com"));
        objects.push(gateway);
        objects.push(route);
    }
    objects.push(backend_tls_policy_system("reviews-tls", "reviews"));

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let covered = translated
        .config
        .upstreams
        .iter()
        .filter(|upstream| upstream.backend_tls_sni.as_deref() == Some("backend.example.com"))
        .count();
    assert!(covered > 0, "the policy must materialize backend TLS");
    assert_eq!(
        covered,
        translated.config.upstreams.len(),
        "the policy stays uniformly in effect across every managed Gateway"
    );

    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    let all = update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .expect("ancestors");
    assert_eq!(
        all.len(),
        1,
        "Ferrum contributes one Service ancestor no matter how many Gateways route to it: {all:?}"
    );
    assert_eq!(
        all[0].get("ancestorRef"),
        Some(&service_ancestor_ref("reviews"))
    );
}

/// A live status with fifteen third-party ancestors leaves exactly one free
/// slot, which Ferrum may use — without disturbing the other controllers'
/// entries and without exceeding the cap.
#[test]
fn backend_tls_policy_status_uses_the_last_free_ancestor_slot() {
    let mut policy = backend_tls_policy_system("reviews-tls", "reviews");
    policy.status = serde_json::json!({ "ancestors": third_party_ancestors(15) });
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert_eq!(
        translated
            .config
            .upstreams
            .first()
            .expect("a representable policy still applies")
            .backend_tls_sni
            .as_deref(),
        Some("backend.example.com")
    );

    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    let all = update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .expect("ancestors");
    assert_eq!(all.len(), 16, "the cap is reached but never exceeded");
    assert_eq!(
        all.iter()
            .filter(|ancestor| {
                ancestor.get("controllerName").and_then(Value::as_str)
                    == Some("example.com/other-controller")
            })
            .count(),
        15,
        "every third-party ancestor is preserved"
    );
    let ferrum = ferrum_ancestors(&update);
    assert_eq!(ferrum.len(), 1);
    assert_eq!(
        ferrum[0].get("ancestorRef"),
        Some(&service_ancestor_ref("reviews"))
    );
}

/// A live status already carrying sixteen third-party ancestors leaves Ferrum
/// no representable slot. Gateway API forbids adding a seventeenth entry, so
/// Ferrum writes nothing, but third-party status must not affect translation.
#[test]
fn backend_tls_policy_with_full_third_party_ancestors_applies_and_writes_no_status() {
    let mut policy = backend_tls_policy_system("reviews-tls", "reviews");
    policy.status = serde_json::json!({ "ancestors": third_party_ancestors(16) });
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert_eq!(translated.config.upstreams.len(), 1);
    assert_eq!(
        translated.config.upstreams[0].backend_tls_sni.as_deref(),
        Some("backend.example.com")
    );
    assert!(!fault_body_mentions(&translated));
    let status = translated
        .backend_tls_policy_statuses
        .first()
        .expect("policy status projection");
    assert!(status.accepted);
    assert_eq!(status.accepted_reason, "Accepted");

    assert!(
        policy_status_update(&objects, "reviews-tls").is_none(),
        "Ferrum must not add a 17th ancestor, and must not disturb the 16 it does not own"
    );
}

#[test]
fn backend_tls_policy_status_reports_unrepresentable_policy_as_invalid_only() {
    let mut policy = backend_tls_policy_system("bad-tls", "reviews");
    policy.spec["validation"]["wellKnownCACertificates"] = serde_json::json!("Unknown");
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];
    let update = policy_status_update(&objects, "bad-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let ancestor = &ancestors[0];
    assert_eq!(
        condition(ancestor, "Accepted")
            .get("reason")
            .and_then(Value::as_str),
        Some("Invalid")
    );
    // The references were fine; only the policy body was unrepresentable.
    let resolved = condition(ancestor, "ResolvedRefs");
    assert_eq!(resolved.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        resolved.get("reason").and_then(Value::as_str),
        Some("ResolvedRefs")
    );
}

#[test]
fn backend_tls_policy_status_reports_target_not_found_when_service_is_absent() {
    // The route still names `reviews` (so a managed Gateway effectively routes
    // to it), but no Service object exists, so the targetRef never resolves.
    let objects = vec![
        gateway_class(),
        gateway(),
        http_route("reviews-route", "reviews", 8080),
        backend_tls_policy_system("reviews-tls", "reviews"),
    ];
    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    assert_eq!(ancestors.len(), 1);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("TargetNotFound")
    );
}

#[test]
fn backend_tls_policy_status_preserves_third_party_ancestors_and_transition_times() {
    let mut policy = backend_tls_policy_system("reviews-tls", "reviews");
    policy.metadata.generation = Some(3);
    // Live status: one third-party ancestor Ferrum must never touch (a Gateway
    // ancestorRef, which Ferrum itself no longer writes), plus a stale Ferrum
    // Service ancestor whose `Accepted` value is about to change and whose
    // `ResolvedRefs` value is not.
    policy.status = serde_json::json!({
        "ancestors": [
            {
                "ancestorRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "default",
                    "name": "edge"
                },
                "controllerName": "example.com/other-controller",
                "conditions": [{
                    "type": "Accepted",
                    "status": "False",
                    "observedGeneration": 3,
                    "reason": "Invalid",
                    "message": "another controller's verdict",
                    "lastTransitionTime": "2020-01-01T00:00:00Z"
                }]
            },
            {
                "ancestorRef": {
                    "group": "",
                    "kind": "Service",
                    "namespace": "default",
                    "name": "reviews"
                },
                "controllerName": FERRUM_GATEWAY_CONTROLLER_NAME,
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "False",
                        "observedGeneration": 2,
                        "reason": "Invalid",
                        "message": "a stale rejection",
                        "lastTransitionTime": "2021-02-03T04:05:06Z"
                    },
                    {
                        "type": "ResolvedRefs",
                        "status": "True",
                        "observedGeneration": 2,
                        "reason": "ResolvedRefs",
                        "message": "All BackendTLSPolicy references accepted by Ferrum",
                        "lastTransitionTime": "2021-02-03T04:05:06Z"
                    }
                ]
            }
        ]
    });
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];

    let update = policy_status_update(&objects, "reviews-tls").expect("policy status update");
    let all = update
        .status
        .get("ancestors")
        .and_then(Value::as_array)
        .expect("ancestors");
    assert_eq!(
        all.iter()
            .filter(|ancestor| {
                ancestor.get("controllerName").and_then(Value::as_str)
                    == Some("example.com/other-controller")
            })
            .count(),
        1,
        "a third-party controller's ancestor must be preserved verbatim, whatever shape it uses: {all:?}"
    );

    let ferrum = ferrum_ancestors(&update);
    assert_eq!(ferrum.len(), 1);
    let accepted = condition(&ferrum[0], "Accepted");
    assert_eq!(accepted.get("status").and_then(Value::as_str), Some("True"));
    assert_ne!(
        accepted.get("lastTransitionTime").and_then(Value::as_str),
        Some("2021-02-03T04:05:06Z"),
        "a changed condition must get a fresh transition time"
    );
    let resolved = condition(&ferrum[0], "ResolvedRefs");
    assert_eq!(
        resolved.get("lastTransitionTime").and_then(Value::as_str),
        Some("2021-02-03T04:05:06Z"),
        "an unchanged condition must keep its transition time"
    );
    assert_eq!(
        resolved.get("observedGeneration").and_then(Value::as_u64),
        Some(3),
        "observedGeneration must advance to the live spec generation"
    );
}

#[test]
fn backend_tls_policy_without_managed_ancestor_gets_no_status_update() {
    // No route reaches the Service, so no managed Gateway carries traffic to it
    // and Ferrum must not claim policy status it is not responsible for.
    let objects = vec![
        gateway_class(),
        gateway(),
        service("orphan", 8080, "http"),
        backend_tls_policy_system("orphan-tls", "orphan"),
    ];
    assert!(policy_status_update(&objects, "orphan-tls").is_none());
}

#[test]
fn backend_tls_policy_both_ca_sources_fails_closed() {
    let mut policy = backend_tls_policy_system("bad-tls", "reviews");
    policy.spec["validation"]["caCertificateRefs"] = serde_json::json!([{
        "group": "",
        "kind": "ConfigMap",
        "name": "auth-cert"
    }]);
    let objects = vec![
        gateway_class(),
        gateway(),
        service("reviews", 8080, "http"),
        ca_configmap("auth-cert"),
        http_route("reviews-route", "reviews", 8080),
        policy,
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.warnings.iter().any(|warning| {
        warning.contains("must not set both caCertificateRefs and wellKnownCACertificates")
    }));
    assert!(translated.config.upstreams.is_empty());
}

// ---------------------------------------------------------------------------
// Service port existence and L4 transport (Gateway API v1.5.1 / GEP-1897)
//
// Two normative clauses drive this block.
//
// `LocalPolicyTargetReferenceWithSectionName`: "If a SectionName is specified,
// but does not exist on the targeted object, the Policy must fail to attach,
// and the policy implementation should record a `ResolvedRefs` or similar
// Condition in the Policy's status."
//
// GEP-1897: "BackendTLSPolicy applies only to TCP traffic. If a policy
// explicitly attaches to a UDP port of a Service (that is, the `targetRef` has
// a `sectionName` specifying a single port or the service has only 1 port), the
// `Accepted: False` Condition with `Reason: Invalid` MUST be set." and "If the
// policy attaches to a mix of TCP and UDP ports, implementations SHOULD include
// a warning in the `Accepted` condition message (`ancestors.conditions`); the
// policy will only be effective for the TCP ports."
// ---------------------------------------------------------------------------

/// A Service whose only port speaks UDP.
fn single_udp_port_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "quic", "port": 8443, "targetPort": 8443, "protocol": "UDP" }
            ]
        }),
    )
}

/// A Service with one TCP port (`http`, 8080) and one UDP port (`quic`, 8443).
fn mixed_transport_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "http", "port": 8080, "targetPort": 8080, "protocol": "TCP" },
                { "name": "quic", "port": 8443, "targetPort": 8443, "protocol": "UDP" }
            ]
        }),
    )
}

/// `http_route` with a caller-chosen listen path so two routes can coexist in
/// one snapshot without colliding on the conflict key.
fn http_route_at(name: &str, service_name: &str, port: u16, path: &str) -> K8sObject {
    object(
        "HTTPRoute",
        name,
        serde_json::json!({
            "parentRefs": [{ "name": "edge" }],
            "hostnames": ["app.example.com"],
            "rules": [{
                "matches": [{ "path": { "type": "PathPrefix", "value": path } }],
                "backendRefs": [{ "name": service_name, "port": port }]
            }]
        }),
    )
}

fn upstream_sni_for(
    translated: &ferrum_edge::config_sources::k8s::K8sTranslation,
    proxy_listen_path: &str,
) -> Option<String> {
    let upstream_id = translated
        .config
        .proxies
        .iter()
        .find(|proxy| proxy.listen_path.as_deref() == Some(proxy_listen_path))
        .and_then(|proxy| proxy.upstream_id.clone())?;
    translated
        .config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == upstream_id)
        .and_then(|upstream| upstream.backend_tls_sni.clone())
}

#[test]
fn backend_tls_policy_nonexistent_section_name_reports_target_not_found() {
    // `htps` is a typo for the real `https` port. Before this check the policy
    // was reported Accepted=True purely because the Service existed, while it
    // applied nowhere.
    let objects = vec![
        gateway_class(),
        gateway(),
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-tls", "api", "htps", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "api-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    assert_eq!(ancestors.len(), 1);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False"),
        "a sectionName that names no Service port must not be Accepted"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("TargetNotFound")
    );
    assert!(
        accepted
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("sectionName") && message.contains("htps")),
        "the message must name the offending field and value: {accepted}"
    );
    // The CA refs resolved fine; ResolvedRefs is reserved for those outcomes.
    let resolved = condition(&ancestors[0], "ResolvedRefs");
    assert_eq!(resolved.get("status").and_then(Value::as_str), Some("True"));

    // "The Policy must fail to attach" — and it must not spill onto the real
    // `https` port the operator meant, nor fail that unrelated port closed.
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "an unattached policy must not project backend TLS"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)),
        "the valid sibling port must keep serving, not fail closed"
    );
    assert!(
        !fault_body_mentions(&translated),
        "a policy that attaches to nothing must not fault unrelated ports"
    );
}

#[test]
fn backend_tls_policy_explicit_udp_section_is_invalid_and_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_transport_service("edge-svc"),
        http_route("udp-route", "edge-svc", 8443),
        sectioned_policy("udp-tls", "edge-svc", "quic", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "udp-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False"),
        "GEP-1897 MUST: a policy explicitly attached to a UDP port is not Accepted"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );

    // Route traffic that actually selects the UDP-targeted policy fails closed
    // rather than originating HTTPS over a UDP port or dropping to plaintext.
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "no HTTPS upstream may be projected onto a UDP Service port"
    );
    assert!(
        fault_body_mentions(&translated),
        "the covered backend must fail closed with the BackendTLSPolicy 500 fault"
    );
}

#[test]
fn backend_tls_policy_udp_section_leaves_the_tcp_sibling_port_alone() {
    // Same policy as above, but the route selects the Service's TCP port. The
    // section-scoped rejection must stay scoped to the port it named.
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_transport_service("edge-svc"),
        http_route("tcp-route", "edge-svc", 8080),
        sectioned_policy("udp-tls", "edge-svc", "quic", "secure.example.com"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        !fault_body_mentions(&translated),
        "a UDP-scoped rejection must not fail an unrelated TCP port closed"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)),
        "the TCP port keeps its pre-policy behaviour"
    );
}

#[test]
fn backend_tls_policy_on_single_udp_port_service_is_invalid_and_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        single_udp_port_service("telemetry"),
        http_route("telemetry-route", "telemetry", 8443),
        // No sectionName: GEP-1897's "the service has only 1 port" clause.
        backend_tls_policy_system("telemetry-tls", "telemetry"),
    ];

    let update = policy_status_update(&objects, "telemetry-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.config.upstreams.is_empty());
    assert!(
        fault_body_mentions(&translated),
        "a single-UDP-port Service under a BackendTLSPolicy must fail closed"
    );
}

#[test]
fn backend_tls_policy_mixed_tcp_udp_warns_and_applies_to_tcp_only() {
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_transport_service("edge-svc"),
        http_route_at("tcp-route", "edge-svc", 8080, "/tcp"),
        http_route_at("udp-route", "edge-svc", 8443, "/udp"),
        backend_tls_policy_system("edge-tls", "edge-svc"),
    ];

    // SHOULD: accepted, with a warning carried in the Accepted message.
    let update = policy_status_update(&objects, "edge-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(accepted.get("status").and_then(Value::as_str), Some("True"));
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Accepted")
    );
    let message = accepted
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("warning") && message.contains("TCP"),
        "the Accepted message must warn about the mixed-transport Service: {message}"
    );

    // "the policy will only be effective for the TCP ports"
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert_eq!(
        upstream_sni_for(&translated, "/tcp").as_deref(),
        Some("backend.example.com"),
        "the TCP port must receive the policy's TLS identity"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.listen_path.as_deref() == Some("/udp")
                && proxy.backend_scheme == Some(BackendScheme::Http)),
        "the UDP port must not be promoted to HTTPS: {:?}",
        translated.config.proxies
    );
    assert!(
        !fault_body_mentions(&translated),
        "a mixed-transport Service is a warning, not a rejection"
    );
}

// ---------------------------------------------------------------------------
// Transport eligibility beyond UDP.
//
// GEP-1897's normative statement is "BackendTLSPolicy applies only to TCP
// traffic"; its two examples happen to name UDP. Ferrum therefore models the
// port transport explicitly and admits only a port proven to be TCP. These
// tests pin the transports a `udp: bool` predicate got wrong: `SCTP` and any
// unrecognized `protocol` value both used to classify as "not UDP" and were
// silently eligible for backend TLS.
// ---------------------------------------------------------------------------

/// A Service whose only port speaks SCTP.
fn single_sctp_port_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "sigtran", "port": 8443, "targetPort": 8443, "protocol": "SCTP" }
            ]
        }),
    )
}

/// A Service with one TCP port (`http`, 8080) and one SCTP port (`sigtran`, 8443).
fn mixed_tcp_sctp_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "http", "port": 8080, "targetPort": 8080, "protocol": "TCP" },
                { "name": "sigtran", "port": 8443, "targetPort": 8443, "protocol": "SCTP" }
            ]
        }),
    )
}

/// A Service whose only port carries a `protocol` Ferrum does not recognize.
///
/// Kubernetes validates this field, so reaching Ferrum means either a future
/// protocol or a tampered/unvalidated object. Either way the transport cannot be
/// proven to be TCP.
fn unrecognized_protocol_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "weird", "port": 8443, "targetPort": 8443, "protocol": "QUIC" }
            ]
        }),
    )
}

/// A Service with one TCP port and two *different* non-TCP ports.
fn tcp_udp_sctp_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "http", "port": 8080, "targetPort": 8080, "protocol": "TCP" },
                { "name": "quic", "port": 8443, "targetPort": 8443, "protocol": "UDP" },
                { "name": "sigtran", "port": 8444, "targetPort": 8444, "protocol": "SCTP" }
            ]
        }),
    )
}

/// A Service whose ports are all non-TCP but of *different* non-TCP kinds.
///
/// Exercises the "no TCP port at all" rejection without letting a single-kind
/// count shortcut stand in for it.
fn udp_and_sctp_only_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "quic", "port": 8443, "targetPort": 8443, "protocol": "UDP" },
                { "name": "sigtran", "port": 8444, "targetPort": 8444, "protocol": "SCTP" }
            ]
        }),
    )
}

/// A Service that spells its TCP protocol in lower case.
///
/// `protocol` is compared case-insensitively, so this must still be TCP — the
/// case-insensitive comparison must not be the only thing standing between a
/// non-canonical spelling and the `Unrecognized` (fail-closed) arm.
fn lowercase_tcp_service(name: &str) -> K8sObject {
    object(
        "Service",
        name,
        serde_json::json!({
            "ports": [
                { "name": "https", "port": 8443, "targetPort": 8443, "protocol": "tcp" }
            ]
        }),
    )
}

#[test]
fn backend_tls_policy_explicit_sctp_section_is_invalid_and_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_tcp_sctp_service("edge-svc"),
        http_route("sctp-route", "edge-svc", 8443),
        sectioned_policy("sctp-tls", "edge-svc", "sigtran", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "sctp-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False"),
        "BackendTLSPolicy applies only to TCP traffic: an SCTP port is not Accepted"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );
    assert!(
        accepted
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.contains("SCTP")),
        "the message must name the ineligible transport: {accepted}"
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        translated.config.upstreams.is_empty(),
        "no HTTPS upstream may be projected onto an SCTP Service port"
    );
    assert!(
        fault_body_mentions(&translated),
        "the covered backend must fail closed with the BackendTLSPolicy 500 fault"
    );
}

#[test]
fn backend_tls_policy_sctp_section_leaves_the_tcp_sibling_port_alone() {
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_tcp_sctp_service("edge-svc"),
        http_route("tcp-route", "edge-svc", 8080),
        sectioned_policy("sctp-tls", "edge-svc", "sigtran", "secure.example.com"),
    ];
    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        !fault_body_mentions(&translated),
        "an SCTP-scoped rejection must not fail an unrelated TCP port closed"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.backend_scheme == Some(BackendScheme::Http)),
        "the TCP port keeps its pre-policy behaviour"
    );
}

#[test]
fn backend_tls_policy_on_single_sctp_port_service_is_invalid_and_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        single_sctp_port_service("sigtran-svc"),
        http_route("sigtran-route", "sigtran-svc", 8443),
        // No sectionName: a Service-wide policy may still apply only to TCP
        // ports, and this Service has none.
        backend_tls_policy_system("sigtran-tls", "sigtran-svc"),
    ];

    let update = policy_status_update(&objects, "sigtran-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False"),
        "a Service-wide policy must not treat SCTP as TCP"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.config.upstreams.is_empty());
    assert!(
        fault_body_mentions(&translated),
        "a single-SCTP-port Service under a BackendTLSPolicy must fail closed"
    );
}

#[test]
fn backend_tls_policy_unrecognized_port_protocol_is_invalid_and_fails_closed() {
    let objects = vec![
        gateway_class(),
        gateway(),
        unrecognized_protocol_service("odd-svc"),
        http_route("odd-route", "odd-svc", 8443),
        backend_tls_policy_system("odd-tls", "odd-svc"),
    ];

    let update = policy_status_update(&objects, "odd-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False"),
        "an unprovable transport must not be assumed to be TCP"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );
    // The raw, cluster-supplied protocol string is untrusted input on a status
    // surface and must not be echoed back into the condition message.
    assert!(
        !accepted
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("QUIC"),
        "the status message must not echo the raw protocol value: {accepted}"
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.config.upstreams.is_empty());
    assert!(
        fault_body_mentions(&translated),
        "an unrecognized-transport port under a BackendTLSPolicy must fail closed"
    );
}

#[test]
fn backend_tls_policy_unrecognized_protocol_section_is_invalid() {
    // Section-scoped variant: the named port itself carries the unrecognized
    // protocol, so the policy governs exactly one ineligible port.
    let objects = vec![
        gateway_class(),
        gateway(),
        unrecognized_protocol_service("odd-svc"),
        http_route("odd-route", "odd-svc", 8443),
        sectioned_policy("odd-tls", "odd-svc", "weird", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "odd-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.config.upstreams.is_empty());
    assert!(fault_body_mentions(&translated));
}

#[test]
fn backend_tls_policy_service_with_only_non_tcp_ports_of_mixed_kinds_is_invalid() {
    let objects = vec![
        gateway_class(),
        gateway(),
        udp_and_sctp_only_service("l4-svc"),
        http_route("l4-route", "l4-svc", 8443),
        backend_tls_policy_system("l4-tls", "l4-svc"),
    ];

    let update = policy_status_update(&objects, "l4-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False"),
        "a Service with no TCP port governs nothing and must not report Accepted"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Invalid")
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(translated.config.upstreams.is_empty());
    assert!(fault_body_mentions(&translated));
}

#[test]
fn backend_tls_policy_mixed_tcp_sctp_warns_and_applies_to_tcp_only() {
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_tcp_sctp_service("edge-svc"),
        http_route_at("tcp-route", "edge-svc", 8080, "/tcp"),
        http_route_at("sctp-route", "edge-svc", 8443, "/sctp"),
        backend_tls_policy_system("edge-tls", "edge-svc"),
    ];

    let update = policy_status_update(&objects, "edge-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("True"),
        "a Service with at least one TCP port is accepted with a warning"
    );
    let message = accepted
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.contains("warning") && message.contains("TCP"),
        "the Accepted message must warn about the mixed-transport Service: {message}"
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert_eq!(
        upstream_sni_for(&translated, "/tcp").as_deref(),
        Some("backend.example.com"),
        "the TCP port must receive the policy's TLS identity"
    );
    assert!(
        translated
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.listen_path.as_deref() == Some("/sctp")
                && proxy.backend_scheme == Some(BackendScheme::Http)),
        "the SCTP port must not be promoted to HTTPS: {:?}",
        translated.config.proxies
    );
    assert!(
        !fault_body_mentions(&translated),
        "a mixed-transport Service is a warning, not a rejection"
    );
}

#[test]
fn backend_tls_policy_mixed_tcp_udp_sctp_applies_to_the_tcp_port_only() {
    // Three transports in one Service: the TCP port takes the policy, and
    // neither non-TCP port is promoted to HTTPS.
    let objects = vec![
        gateway_class(),
        gateway(),
        tcp_udp_sctp_service("edge-svc"),
        http_route_at("tcp-route", "edge-svc", 8080, "/tcp"),
        http_route_at("udp-route", "edge-svc", 8443, "/udp"),
        http_route_at("sctp-route", "edge-svc", 8444, "/sctp"),
        backend_tls_policy_system("edge-tls", "edge-svc"),
    ];

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert_eq!(
        upstream_sni_for(&translated, "/tcp").as_deref(),
        Some("backend.example.com")
    );
    for plaintext_path in ["/udp", "/sctp"] {
        assert!(
            translated
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.listen_path.as_deref() == Some(plaintext_path)
                    && proxy.backend_scheme == Some(BackendScheme::Http)),
            "{plaintext_path} must keep its pre-policy plaintext behaviour: {:?}",
            translated.config.proxies
        );
        assert!(
            upstream_sni_for(&translated, plaintext_path).is_none(),
            "{plaintext_path} must not receive the policy's TLS identity"
        );
    }
    assert!(!fault_body_mentions(&translated));
}

#[test]
fn backend_tls_policy_omitted_port_protocol_defaults_to_tcp_and_applies() {
    // `spec.ports[].protocol` is optional and Kubernetes defaults it to TCP, so
    // an omitted value must stay eligible — the fail-closed `Unrecognized` arm
    // must not swallow the ordinary case.
    let objects = vec![
        gateway_class(),
        gateway(),
        // `multi_port_service` omits `protocol` on both ports.
        multi_port_service("api"),
        http_route("api-route", "api", 8443),
        backend_tls_policy_system("api-tls", "api"),
    ];

    let update = policy_status_update(&objects, "api-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("True"),
        "an omitted `protocol` defaults to TCP and stays eligible"
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("Accepted")
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("a default-protocol Service port must receive backend TLS");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("backend.example.com")
    );
    assert!(!fault_body_mentions(&translated));
}

#[test]
fn backend_tls_policy_lowercase_tcp_protocol_is_recognized_as_tcp() {
    let objects = vec![
        gateway_class(),
        gateway(),
        lowercase_tcp_service("api"),
        http_route("api-route", "api", 8443),
        sectioned_policy("api-tls", "api", "https", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "api-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("True"),
        "`protocol: tcp` is TCP; case must not push it onto the fail-closed arm"
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("a lower-case TCP port must receive backend TLS");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secure.example.com")
    );
    assert!(!fault_body_mentions(&translated));
}

#[test]
fn backend_tls_policy_section_name_on_explicit_tcp_port_applies() {
    // sectionName hit on an explicitly-`TCP` port: the transport model must not
    // have made the explicit spelling any less eligible than the omitted one.
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_tcp_sctp_service("edge-svc"),
        http_route("tcp-route", "edge-svc", 8080),
        sectioned_policy("tcp-tls", "edge-svc", "http", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "tcp-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(accepted.get("status").and_then(Value::as_str), Some("True"));

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    let upstream = translated
        .config
        .upstreams
        .first()
        .expect("a sectionName-matched TCP port must receive backend TLS");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("secure.example.com")
    );
    assert!(!fault_body_mentions(&translated));
}

#[test]
fn backend_tls_policy_section_name_miss_on_non_tcp_service_reports_target_not_found() {
    // A `sectionName` that names no port is `TargetNotFound` regardless of the
    // transports the Service does declare: the miss is diagnosed before any
    // transport conclusion, so it must not be reported as `Invalid`.
    let objects = vec![
        gateway_class(),
        gateway(),
        mixed_tcp_sctp_service("edge-svc"),
        http_route("tcp-route", "edge-svc", 8080),
        sectioned_policy("typo-tls", "edge-svc", "sigtan", "secure.example.com"),
    ];

    let update = policy_status_update(&objects, "typo-tls").expect("policy status update");
    let ancestors = ferrum_ancestors(&update);
    let accepted = condition(&ancestors[0], "Accepted");
    assert_eq!(
        accepted.get("status").and_then(Value::as_str),
        Some("False")
    );
    assert_eq!(
        accepted.get("reason").and_then(Value::as_str),
        Some("TargetNotFound"),
        "a sectionName miss is TargetNotFound, not an Invalid transport verdict"
    );

    let translated = translate_k8s_objects(&objects, options()).expect("translate");
    assert!(
        !fault_body_mentions(&translated),
        "a policy that attaches to nothing must not fault the Service's valid ports"
    );
}

// ---------------------------------------------------------------------------
// Live: the SNI health probe must speak HTTP/1.1
// ---------------------------------------------------------------------------
//
// A `BackendTLSPolicy` `validation.hostname` becomes `backend_tls_sni`, and the
// active HTTP probe has to offer that server name or it reports a healthy
// backend as unhealthy. reqwest exposes no per-request server-name hook, so the
// override goes in the probe URL's authority while the REAL target authority is
// carried in an explicit `Host` header.
//
// That pairing only holds over HTTP/1.1. HTTP/2 derives `:authority` from the
// URI — i.e. from the server name — so an h2-negotiated probe would show the
// backend the override instead of the target it is probing. The fixture below
// therefore ADVERTISES `h2` ahead of `http/1.1` while speaking raw HTTP/1.1: a
// probe client that is not restricted to H1 selects h2, sends a connection
// preface instead of a request, and records no `Host` at all.

static INIT_PROBE_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_PROBE_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct ProbeCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

fn probe_ca(cn: &str) -> ProbeCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    ProbeCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

/// Leaf valid for `dns_san` only — the policy hostname, never the dial target.
fn probe_leaf(ca: &ProbeCa, dns_san: &str) -> (String, String) {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params = CertificateParams::new(vec![dns_san.to_string()]).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_san);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    (cert.pem(), key_pair.serialize_pem())
}

/// What one accepted connection revealed about the probe.
#[derive(Debug, Clone)]
struct ObservedProbe {
    /// TLS server name the client presented.
    server_name: Option<String>,
    /// ALPN protocol the connection settled on.
    alpn: Option<String>,
    /// `Host` header of the HTTP/1.1 request, if the client sent a request at
    /// all. An h2 client writes a connection preface here instead, so this
    /// stays `None` — which is exactly the regression this fixture detects.
    host_header: Option<String>,
}

/// Accept task, bound port, and per-connection observations.
type ProbeFixture = (tokio::task::JoinHandle<()>, u16, ProbeLog);

type ProbeLog = Arc<Mutex<Vec<ObservedProbe>>>;

/// TLS listener that ADVERTISES `h2` ahead of `http/1.1` but only ever speaks
/// raw HTTP/1.1.
async fn start_h2_first_raw_h1_backend(cert_pem: &str, key_pem: &str) -> ProbeFixture {
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse backend cert");
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .expect("parse backend key")
        .expect("backend key present");
    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("backend server cert");
    // The whole point of the fixture: h2 is offered FIRST.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    let observed: ProbeLog = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&observed);

    let handle = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let recorder = Arc::clone(&recorder);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let (_, conn) = stream.get_ref();
                let server_name = conn.server_name().map(str::to_string);
                let alpn = conn.alpn_protocol().map(alpn_label);
                let mut buf = vec![0u8; 4096];
                let read = stream.read(&mut buf).await.unwrap_or(0);
                let request_head = String::from_utf8_lossy(&buf[..read]).into_owned();
                let observation = ObservedProbe {
                    server_name,
                    alpn,
                    host_header: h1_host_header(&request_head),
                };
                if let Ok(mut seen) = recorder.lock() {
                    seen.push(observation);
                }
                // Answer raw HTTP/1.1 regardless: an h2 client cannot use this,
                // which is what makes an unrestricted probe fail loudly.
                let body = br#"{"status":"ok"}"#;
                let response_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response_head.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    (handle, port, observed)
}

/// Owned rendering of a negotiated ALPN protocol identifier.
fn alpn_label(protocol: &[u8]) -> String {
    String::from_utf8_lossy(protocol).into_owned()
}

/// `Host` value of a raw HTTP/1.1 request head, if this is a request at all.
fn h1_host_header(head: &str) -> Option<String> {
    if !head.starts_with("GET ") && !head.starts_with("HEAD ") {
        return None;
    }
    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread")]
async fn backend_tls_policy_sni_probe_speaks_http1_and_shows_the_real_target_authority() {
    ensure_crypto_provider();

    const POLICY_HOSTNAME: &str = "backend.example.com";
    let ca = probe_ca("backend-tls-policy-probe-ca");
    let (leaf_cert, leaf_key) = probe_leaf(&ca, POLICY_HOSTNAME);
    let (_backend, backend_port, observed) =
        start_h2_first_raw_h1_backend(&leaf_cert, &leaf_key).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.cert_pem.as_bytes()).expect("write CA");

    // What a `BackendTLSPolicy` with `validation.hostname` translates to: the
    // SNI override plus the policy's CA, dialing the real target.
    let upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "reviews",
        "namespace": "ferrum",
        "targets": [{ "host": "127.0.0.1", "port": backend_port, "weight": 100 }],
        "backend_tls_sni": POLICY_HOSTNAME,
        "backend_tls_server_ca_cert_path": ca_path.to_string_lossy(),
        "backend_tls_verify_server_cert": true,
        "health_checks": {
            "active": {
                "http_path": "/healthz",
                "interval_seconds": 1,
                "timeout_ms": 4000,
                "healthy_threshold": 1,
                "unhealthy_threshold": 1,
                "healthy_status_codes": [200],
                "use_tls": true,
                "probe_type": "http"
            }
        }
    }))
    .expect("upstream fixture");

    let config = GatewayConfig {
        upstreams: vec![upstream],
        ..GatewayConfig::default()
    };

    let dns_cache = DnsCache::new(DnsConfig::default());
    let checker = HealthChecker::with_pool_config(&PoolConfig::default(), dns_cache);
    checker.start(&config);

    let deadline = Instant::now() + Duration::from_secs(20);
    let probe = loop {
        let first = match observed.lock() {
            Ok(seen) => seen.first().cloned(),
            Err(poisoned) => poisoned.into_inner().first().cloned(),
        };
        if let Some(probe) = first {
            break probe;
        }
        assert!(
            Instant::now() < deadline,
            "the backend TLS SNI health probe never reached the backend"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    for handle in checker.take_active_check_handles() {
        handle.abort();
    }

    assert_eq!(
        probe.server_name.as_deref(),
        Some(POLICY_HOSTNAME),
        "the probe must present the BackendTLSPolicy hostname as its TLS server name"
    );
    assert_eq!(
        probe.alpn.as_deref(),
        Some("http/1.1"),
        "the SNI probe client must not negotiate h2 even when the backend offers it first"
    );
    let expected_authority = format!("127.0.0.1:{backend_port}");
    assert_eq!(
        probe.host_header.as_deref(),
        Some(expected_authority.as_str()),
        "the backend must be shown the REAL target authority, not the server name"
    );
}
