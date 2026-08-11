//! Gateway API multi-certificate frontend TLS translation (issues #3267/#3268).
//!
//! Covers the translator's decisions over a whole snapshot: which certificates
//! a namespace ends up serving, which listener wins an SNI hostname collision,
//! which certificate is the deterministic fallback, and how reload/delete and
//! Secret rotation move that set. The runtime half — actually selecting a
//! certificate per ClientHello — lives in
//! `tests/integration/gateway_multi_cert_sni_tests.rs`.

use base64::Engine as _;
use ferrum_edge::config::types::{
    FrontendTlsCertificateSource, GatewayConfig, MAX_FRONTEND_TLS_CERTIFICATE_SOURCES,
    default_namespace,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslation, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        default_namespace(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: if kind == "Secret" {
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

fn created_at(mut object: K8sObject, timestamp: &str) -> K8sObject {
    object.metadata.creation_timestamp = Some(timestamp.to_string());
    object
}

fn tls_secret(name: &str, namespace: &str) -> K8sObject {
    object(
        "Secret",
        namespace,
        name,
        json!({
            "type": "kubernetes.io/tls",
            "data": {
                "tls.crt": base64::engine::general_purpose::STANDARD
                    .encode(include_str!("../../certs/server.crt")),
                "tls.key": base64::engine::general_purpose::STANDARD
                    .encode(include_str!("../../certs/server.key")),
            }
        }),
    )
}

/// Same Secret name, a different but equally VALID pair — the shape a
/// cert-manager rotation takes. Rotating to invalid bytes would only prove the
/// fail-closed path, not that a valid rotation moves the source digest.
fn rotated_tls_secret(name: &str, namespace: &str) -> K8sObject {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    let params = rcgen::CertificateParams::new(vec!["rotated.example.com".to_string()])
        .expect("certificate params");
    let certificate = params.self_signed(&key_pair).expect("self-signed cert");
    let mut secret = tls_secret(name, namespace);
    let encode = base64::engine::general_purpose::STANDARD;
    secret.spec["data"]["tls.crt"] = json!(encode.encode(certificate.pem()));
    secret.spec["data"]["tls.key"] = json!(encode.encode(key_pair.serialize_pem()));
    secret
}

fn https_listener(name: &str, port: u64, hostname: Option<&str>, secrets: &[&str]) -> Value {
    let mut listener = json!({
        "name": name,
        "port": port,
        "protocol": "HTTPS",
        "tls": {
            "certificateRefs": secrets
                .iter()
                .map(|secret| json!({"name": secret}))
                .collect::<Vec<_>>()
        },
        "allowedRoutes": {"namespaces": {"from": "All"}}
    });
    if let Some(hostname) = hostname {
        listener["hostname"] = json!(hostname);
    }
    listener
}

fn gateway(namespace: &str, name: &str, listeners: Vec<Value>) -> K8sObject {
    object(
        "Gateway",
        namespace,
        name,
        json!({"gatewayClassName": "ferrum", "listeners": listeners}),
    )
}

fn route(namespace: &str, name: &str, gateway: &str, section: &str, path: &str) -> K8sObject {
    object(
        "HTTPRoute",
        namespace,
        name,
        json!({
            "parentRefs": [{"name": gateway, "sectionName": section}],
            "rules": [{
                "matches": [{"path": {"type": "PathPrefix", "value": path}}],
                "backendRefs": [{"name": "backend", "port": 8080}]
            }]
        }),
    )
}

fn translate(objects: &[K8sObject]) -> K8sTranslation {
    translate_k8s_objects(objects, options()).expect("translation succeeds")
}

fn cert_paths(config: &GatewayConfig) -> Vec<String> {
    config
        .frontend_tls_certificate_sources
        .iter()
        .map(|source| source.cert_path.clone())
        .collect()
}

#[test]
fn one_listener_serves_every_certificate_ref() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![https_listener(
                "https",
                443,
                None,
                &["rsa-cert", "ecdsa-cert"],
            )],
        ),
        tls_secret("rsa-cert", "ferrum"),
        tls_secret("ecdsa-cert", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    assert!(
        cert_paths(&result.config)
            .iter()
            .any(|path| path.starts_with("k8s://ferrum/rsa-cert#tls.crt?sha256="))
    );
    assert!(
        cert_paths(&result.config)
            .iter()
            .any(|path| path.starts_with("k8s://ferrum/ecdsa-cert#tls.crt?sha256="))
    );
    assert!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.gateway == "edge" && source.listener == "https")
    );
}

#[test]
fn independent_gateways_in_one_namespace_each_keep_their_certificate() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("a.example.com"),
                &["cert-a"],
            )],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener(
                "https",
                8443,
                Some("b.example.com"),
                &["cert-b"],
            )],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
        route("ferrum", "route-a", "edge-a", "https", "/a"),
        route("ferrum", "route-b", "edge-b", "https", "/b"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    let gateways: Vec<&str> = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .map(|source| source.gateway.as_str())
        .collect();
    assert!(gateways.contains(&"edge-a") && gateways.contains(&"edge-b"));

    // Both listeners serve route traffic; issue #3268's symptom was the second
    // Gateway keeping status while its routes stayed unmaterialized.
    for route_name in ["route-a", "route-b"] {
        assert!(
            result
                .config
                .proxies
                .iter()
                .any(|proxy| proxy.id.contains(route_name)),
            "{route_name} should be materialized"
        );
    }
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.contains("unmaterialized"))
    );
}

#[test]
fn cross_namespace_same_named_listenersets_keep_distinct_runtime_identities() {
    let mut parent = gateway(
        "serving",
        "edge",
        vec![json!({
            "name": "http",
            "port": 80,
            "protocol": "HTTP",
            "allowedRoutes": {"namespaces": {"from": "All"}}
        })],
    );
    parent.spec["allowedListeners"] = json!({"namespaces": {"from": "All"}});

    let listenerset = |namespace: &str, port: u64, hostname: &str, secret: &str| {
        object(
            "ListenerSet",
            namespace,
            "shared",
            json!({
                "parentRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "namespace": "serving",
                    "name": "edge"
                },
                "listeners": [https_listener("https", port, Some(hostname), &[secret])]
            }),
        )
    };
    let result = translate_k8s_objects(
        &[
            parent,
            listenerset("team-a", 8443, "a.example.com", "cert-a"),
            listenerset("team-b", 9443, "b.example.com", "cert-b"),
            tls_secret("cert-a", "team-a"),
            tls_secret("cert-b", "team-b"),
        ],
        options().with_source_namespaces(vec![
            "serving".to_string(),
            "team-a".to_string(),
            "team-b".to_string(),
        ]),
    )
    .expect("cross-namespace ListenerSets translate");

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    let sources_by_hostname: HashMap<_, _> = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .map(|source| (source.hostname.as_deref(), source))
        .collect();
    let team_a = sources_by_hostname
        .get(&Some("a.example.com"))
        .expect("team-a hostname provenance");
    let team_b = sources_by_hostname
        .get(&Some("b.example.com"))
        .expect("team-b hostname provenance");

    assert_eq!(team_a.namespace, "serving");
    assert_eq!(team_b.namespace, "serving");
    assert_eq!(team_a.gateway, "ListenerSet:team-a:shared");
    assert_eq!(team_b.gateway, "ListenerSet:team-b:shared");
    assert_eq!(
        team_a.listener_identity(),
        "serving/ListenerSet:team-a:shared/https"
    );
    assert_eq!(
        team_b.listener_identity(),
        "serving/ListenerSet:team-b:shared/https"
    );
    assert_ne!(team_a.listener_identity(), team_b.listener_identity());
    assert_ne!(team_a.listener_identity(), "serving/shared/https");
    assert_ne!(team_b.listener_identity(), "serving/shared/https");
}

#[test]
fn listener_hostname_and_default_marker_are_deterministic() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![
                https_listener("named", 443, Some("API.Example.COM."), &["named-cert"]),
                https_listener("catch-all", 8443, None, &["catch-all-cert"]),
            ],
        ),
        tls_secret("named-cert", "ferrum"),
        tls_secret("catch-all-cert", "ferrum"),
    ]);

    let named = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .find(|source| source.listener == "named")
        .expect("named listener retained");
    // Hostnames are normalized the same way route hostnames are: trailing dot
    // stripped, ASCII-lowercased.
    assert_eq!(named.hostname.as_deref(), Some("api.example.com"));
    assert!(!named.default_certificate);

    let catch_all = result
        .config
        .frontend_tls_certificate_sources
        .iter()
        .find(|source| source.listener == "catch-all")
        .expect("catch-all listener retained");
    assert_eq!(catch_all.hostname, None);
    assert!(
        catch_all.default_certificate,
        "a catch-all listener takes the fallback slot over a hostname-scoped one"
    );
    assert_eq!(
        result.config.frontend_tls_cert_path.as_deref(),
        Some(catch_all.cert_path.as_str()),
        "the legacy fallback projection tracks the marked default"
    );
}

#[test]
fn hostname_collision_fails_the_younger_listener_closed() {
    let older = created_at(
        gateway(
            "ferrum",
            "edge-old",
            vec![https_listener(
                "https",
                443,
                Some("shop.example.com"),
                &["cert-a"],
            )],
        ),
        "2026-01-01T00:00:00Z",
    );
    let younger = created_at(
        gateway(
            "ferrum",
            "edge-new",
            vec![https_listener(
                "https",
                8443,
                Some("shop.example.com"),
                &["cert-b"],
            )],
        ),
        "2026-06-01T00:00:00Z",
    );

    let result = translate(&[
        // Deliberately listed younger-first: the winner must come from the
        // creation timestamp, never from informer/list order.
        younger,
        older,
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
        route("ferrum", "route-old", "edge-old", "https", "/"),
        route("ferrum", "route-new", "edge-new", "https", "/new"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        result.config.frontend_tls_certificate_sources[0].gateway, "edge-old",
        "the older Gateway wins the contested hostname"
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("edge-new")
                && warning.contains("shop.example.com")
                && warning.contains("unmaterialized"))
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .all(|proxy| !proxy.id.contains("route-new")),
        "the losing listener must not serve route traffic under an ambiguous certificate"
    );
}

#[test]
fn rejected_listener_cannot_win_a_certificate_hostname_collision() {
    let mut rejected = https_listener("https", 443, Some("shop.example.com"), &["rejected-cert"]);
    rejected["allowedRoutes"]["namespaces"]["from"] = json!("Invalid");
    let rejected_gateway = created_at(
        gateway("ferrum", "edge-rejected", vec![rejected]),
        "2026-01-01T00:00:00Z",
    );
    let valid_gateway = created_at(
        gateway(
            "ferrum",
            "edge-valid",
            vec![https_listener(
                "https",
                8443,
                Some("shop.example.com"),
                &["valid-cert"],
            )],
        ),
        "2026-06-01T00:00:00Z",
    );

    let result = translate(&[
        rejected_gateway,
        valid_gateway,
        tls_secret("rejected-cert", "ferrum"),
        tls_secret("valid-cert", "ferrum"),
        route("ferrum", "route-valid", "edge-valid", "https", "/"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        result.config.frontend_tls_certificate_sources[0].gateway,
        "edge-valid"
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.id.contains("route-valid")),
        "a rejected older listener must not evict the valid listener or its routes"
    );
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.contains("already served with a different certificate"))
    );
}

#[test]
fn identical_certificate_on_one_hostname_is_not_a_collision() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("shop.example.com"),
                &["shared-cert"],
            )],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener(
                "https",
                8443,
                Some("shop.example.com"),
                &["shared-cert"],
            )],
        ),
        tls_secret("shared-cert", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| warning.contains("already served with a different certificate"))
    );
}

#[test]
fn catch_all_listeners_with_different_certificates_do_not_collide() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener("https", 443, None, &["cert-a"])],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener("https", 8443, None, &["cert-b"])],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 2);
    assert_eq!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.default_certificate)
            .count(),
        1,
        "one namespace has exactly one fallback certificate"
    );
}

#[test]
fn one_unresolved_reference_withdraws_only_its_own_listener() {
    let result = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![
                https_listener("good", 443, Some("good.example.com"), &["good-cert"]),
                // Second ref never exists: the whole listener fails closed
                // rather than serving a partial set.
                https_listener(
                    "partial",
                    8443,
                    Some("partial.example.com"),
                    &["good-cert", "missing-cert"],
                ),
            ],
        ),
        tls_secret("good-cert", "ferrum"),
    ]);

    assert_eq!(result.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        result.config.frontend_tls_certificate_sources[0].listener,
        "good"
    );
    assert!(result.warnings.iter().any(|warning| {
        warning.contains("spec.listeners[].tls.certificateRefs") && warning.contains("partial")
    }));
}

#[test]
fn cross_namespace_secret_requires_a_reference_grant() {
    let gateway_object = gateway(
        "ferrum",
        "edge",
        vec![json!({
            "name": "https",
            "port": 443,
            "protocol": "HTTPS",
            "tls": {"certificateRefs": [{"name": "shared-cert", "namespace": "certs"}]}
        })],
    );
    let secret = tls_secret("shared-cert", "certs");
    let grant = object(
        "ReferenceGrant",
        "certs",
        "allow-edge",
        json!({
            "from": [{
                "group": "gateway.networking.k8s.io",
                "kind": "Gateway",
                "namespace": "ferrum"
            }],
            "to": [{"group": "", "kind": "Secret", "name": "shared-cert"}]
        }),
    );
    fn namespaces() -> K8sTranslationOptions {
        options().with_source_namespaces(vec!["ferrum".to_string(), "certs".to_string()])
    }

    let denied = translate_k8s_objects(&[gateway_object.clone(), secret.clone()], namespaces())
        .expect("translation succeeds");
    assert!(
        denied.config.frontend_tls_certificate_sources.is_empty(),
        "an unauthorized cross-namespace Secret must not be served"
    );

    let allowed = translate_k8s_objects(&[gateway_object, secret, grant], namespaces())
        .expect("translation succeeds");
    assert_eq!(allowed.config.frontend_tls_certificate_sources.len(), 1);
    assert!(
        allowed.config.frontend_tls_certificate_sources[0]
            .cert_path
            .starts_with("k8s://certs/shared-cert#tls.crt?sha256=")
    );
    assert_eq!(
        allowed.config.frontend_tls_certificate_sources[0].namespace, "ferrum",
        "ownership is the Gateway's namespace, never the Secret's"
    );
}

#[test]
fn secret_rotation_changes_only_the_rotated_certificate_source() {
    let objects = |rotate_b: bool| {
        vec![
            gateway(
                "ferrum",
                "edge",
                vec![
                    https_listener("a", 443, Some("a.example.com"), &["cert-a"]),
                    https_listener("b", 8443, Some("b.example.com"), &["cert-b"]),
                ],
            ),
            tls_secret("cert-a", "ferrum"),
            if rotate_b {
                rotated_tls_secret("cert-b", "ferrum")
            } else {
                tls_secret("cert-b", "ferrum")
            },
        ]
    };

    let before = translate(&objects(false));
    let after = translate(&objects(true));

    let source_for = |result: &K8sTranslation, listener: &str| {
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .find(|source| source.listener == listener)
            .map(|source| source.cert_path.clone())
    };

    assert!(
        source_for(&after, "b").is_some(),
        "the rotated Secret stays valid"
    );
    assert_eq!(
        source_for(&before, "a"),
        source_for(&after, "a"),
        "an untouched certificate keeps its stable source string"
    );
    assert_ne!(
        source_for(&before, "b"),
        source_for(&after, "b"),
        "a rotated Secret must change its own source digest so the CP broadcasts it"
    );
}

#[test]
fn deleting_one_gateway_withdraws_only_its_own_certificates() {
    let all = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("a.example.com"),
                &["cert-a"],
            )],
        ),
        gateway(
            "ferrum",
            "edge-b",
            vec![https_listener(
                "https",
                8443,
                Some("b.example.com"),
                &["cert-b"],
            )],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ]);
    assert_eq!(all.config.frontend_tls_certificate_sources.len(), 2);

    // Reload with edge-b gone; edge-a's certificate is untouched.
    let remaining = translate(&[
        gateway(
            "ferrum",
            "edge-a",
            vec![https_listener(
                "https",
                443,
                Some("a.example.com"),
                &["cert-a"],
            )],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ]);
    assert_eq!(remaining.config.frontend_tls_certificate_sources.len(), 1);
    assert_eq!(
        remaining.config.frontend_tls_certificate_sources[0].gateway,
        "edge-a"
    );

    // Reload with every Gateway gone: nothing is left to serve.
    let none = translate(&[tls_secret("cert-a", "ferrum")]);
    assert!(none.config.frontend_tls_certificate_sources.is_empty());
    assert_eq!(none.config.frontend_tls_cert_path, None);
    assert_eq!(none.config.frontend_tls_key_path, None);
}

#[test]
fn snapshot_certificate_count_is_capped() {
    let mut objects = vec![tls_secret("cert", "ferrum")];
    let listeners: Vec<Value> = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 5)
        .map(|index| {
            https_listener(
                &format!("listener-{index}"),
                (10000 + index) as u64,
                Some(&format!("host-{index}.example.com")),
                &["cert"],
            )
        })
        .collect();
    objects.push(gateway("ferrum", "edge", listeners));

    let result = translate(&objects);

    assert_eq!(
        result.config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
    );
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.contains("Gateway frontend TLS certificate limit"))
    );
}

#[test]
fn certificate_cap_is_isolated_per_serving_namespace() {
    let attacker_listeners: Vec<Value> = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES)
        .map(|index| {
            https_listener(
                &format!("listener-{index}"),
                (10000 + index) as u64,
                Some(&format!("host-{index}.attacker.example.com")),
                &["attacker-cert"],
            )
        })
        .collect();
    // Multi-tenant CP snapshots watch every serving namespace; default options
    // only include `ferrum`, which would silently drop both fixtures.
    let result = translate_k8s_objects(
        &[
            gateway("aaa-attacker", "edge", attacker_listeners),
            gateway(
                "zzz-victim",
                "edge",
                vec![https_listener(
                    "https",
                    443,
                    Some("victim.example.com"),
                    &["victim-cert"],
                )],
            ),
            tls_secret("attacker-cert", "aaa-attacker"),
            tls_secret("victim-cert", "zzz-victim"),
            route("zzz-victim", "victim-route", "edge", "https", "/"),
        ],
        options()
            .with_source_namespaces(vec!["aaa-attacker".to_string(), "zzz-victim".to_string()]),
    )
    .expect("translation succeeds");

    assert_eq!(
        result.config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1
    );
    assert_eq!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.namespace == "aaa-attacker")
            .count(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES,
        "attacker may fill its own per-serving-namespace budget"
    );
    assert!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| source.namespace == "zzz-victim" && source.gateway == "edge")
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .any(|proxy| proxy.namespace == "zzz-victim" && proxy.id.contains("victim-route")),
        "another namespace filling its budget must not withdraw the victim route"
    );
}

#[test]
fn cap_promotion_is_rechecked_for_physical_port_conflicts() {
    let fill_listeners: Vec<Value> = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES - 1)
        .map(|index| {
            https_listener(
                &format!("fill-{index:03}"),
                (10000 + index) as u64,
                Some(&format!("fill-{index}.example.com")),
                &["cert"],
            )
        })
        .collect();
    let conflicting_gateway = |name: &str, port: u64| {
        gateway(
            "ferrum",
            name,
            vec![
                json!({
                    "name": "plain",
                    "port": port,
                    "protocol": "HTTP",
                    "allowedRoutes": {"namespaces": {"from": "All"}}
                }),
                https_listener(
                    "secure",
                    port,
                    Some(&format!("{name}.example.com")),
                    &["cert"],
                ),
            ],
        )
    };
    let result = translate(&[
        gateway("ferrum", "a-fill", fill_listeners),
        conflicting_gateway("b-refused", 30000),
        conflicting_gateway("c-promoted", 30001),
        tls_secret("cert", "ferrum"),
    ]);

    assert_eq!(
        result.config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES - 1,
        "neither physically conflicting TLS listener may survive finalization"
    );
    assert!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.gateway == "a-fill")
    );
    for gateway in ["b-refused", "c-promoted"] {
        for listener in ["plain", "secure"] {
            assert!(
                result.listener_conflicts.iter().any(|(key, conflict)| {
                    key.gateway == gateway
                        && key.listener == listener
                        && conflict.reason == "ProtocolConflict"
                }),
                "{gateway}/{listener} must be refused after cap admission reaches a fixed point: {:?}",
                result.listener_conflicts
            );
        }
    }
}

#[test]
fn snapshot_cap_never_retains_a_partial_listener_certificate_set() {
    let mut listeners: Vec<Value> = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES - 1)
        .map(|index| {
            https_listener(
                &format!("a-{index:03}"),
                (10000 + index) as u64,
                Some(&format!("host-{index}.example.com")),
                &["cert-a"],
            )
        })
        .collect();
    listeners.push(https_listener(
        "zz-bundle",
        20000,
        Some("bundle.example.com"),
        &["cert-a", "cert-b"],
    ));
    let result = translate(&[
        gateway("ferrum", "edge", listeners),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
        route("ferrum", "overflow-route", "edge", "zz-bundle", "/overflow"),
    ]);

    assert_eq!(
        result.config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES - 1,
        "the one remaining slot cannot admit a two-certificate listener atomically"
    );
    assert!(
        result
            .config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.listener != "zz-bundle"),
        "no prefix of the overflowing listener's certificateRefs may remain served"
    );
    assert!(
        result
            .config
            .proxies
            .iter()
            .all(|proxy| !proxy.id.contains("overflow-route")),
        "routes for the atomically withdrawn listener must also stay unmaterialized"
    );
    assert!(result.warnings.iter().any(|warning| {
        warning.contains("zz-bundle")
            && warning.contains("certificate set and route traffic unmaterialized")
    }));
}

#[test]
fn native_normalization_preserves_oversized_certificate_sets_for_rejection() {
    let mut ordered_candidates = GatewayConfig {
        frontend_tls_certificate_sources: ["declared-first", "declared-second"]
            .into_iter()
            .map(|suffix| FrontendTlsCertificateSource {
                namespace: "ferrum".to_string(),
                gateway: "edge".to_string(),
                listener: "https".to_string(),
                cert_path: format!("/certs/{suffix}.crt"),
                key_path: format!("/certs/{suffix}.key"),
                ..Default::default()
            })
            .collect(),
        ..GatewayConfig::default()
    };
    ordered_candidates.normalize_fields();
    assert_eq!(
        ordered_candidates.frontend_tls_certificate_sources[0].cert_path,
        "/certs/declared-first.crt",
        "normalization must preserve certificateRefs order within a listener"
    );

    let mut sources: Vec<FrontendTlsCertificateSource> = (0..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES
        - 1)
        .map(|index| FrontendTlsCertificateSource {
            namespace: "ferrum".to_string(),
            gateway: "edge".to_string(),
            listener: format!("a-{index:03}"),
            hostname: Some(format!("host-{index}.example.com")),
            cert_path: format!("/certs/{index}.crt"),
            key_path: format!("/certs/{index}.key"),
            default_certificate: false,
        })
        .collect();
    for suffix in ["rsa", "ecdsa"] {
        sources.push(FrontendTlsCertificateSource {
            namespace: "ferrum".to_string(),
            gateway: "edge".to_string(),
            listener: "zz-bundle".to_string(),
            hostname: Some("bundle.example.com".to_string()),
            cert_path: format!("/certs/bundle-{suffix}.crt"),
            key_path: format!("/certs/bundle-{suffix}.key"),
            default_certificate: true,
        });
    }
    let mut config = GatewayConfig {
        frontend_tls_certificate_sources: sources,
        ..GatewayConfig::default()
    };

    config.normalize_fields();

    assert_eq!(
        config.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1
    );
    assert_eq!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.listener == "zz-bundle")
            .count(),
        2
    );
    assert_eq!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.default_certificate)
            .count(),
        1
    );
    assert!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .any(|source| Some(source.cert_path.as_str())
                == config.frontend_tls_cert_path.as_deref()),
        "the legacy fallback projection must point at one retained source until the snapshot is rejected"
    );
    let errors = config
        .validate_all_fields(30)
        .expect_err("an oversized native snapshot must be rejected");
    assert!(errors.iter().any(|error| error.contains("admission limit")));

    let oversized_group: Vec<FrontendTlsCertificateSource> = (0
        ..MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1)
        .map(|index| FrontendTlsCertificateSource {
            namespace: "ferrum".to_string(),
            gateway: "edge".to_string(),
            listener: "only-listener".to_string(),
            cert_path: format!("/certs/oversized-{index}.crt"),
            key_path: format!("/certs/oversized-{index}.key"),
            ..Default::default()
        })
        .collect();
    let mut only_oversized = GatewayConfig {
        frontend_tls_cert_path: Some("/certs/oversized-0.crt".to_string()),
        frontend_tls_key_path: Some("/certs/oversized-0.key".to_string()),
        frontend_tls_source_namespace: Some("ferrum".to_string()),
        frontend_tls_certificate_sources: oversized_group,
        ..GatewayConfig::default()
    };
    only_oversized.normalize_fields();
    assert_eq!(
        only_oversized.frontend_tls_certificate_sources.len(),
        MAX_FRONTEND_TLS_CERTIFICATE_SOURCES + 1
    );
    let errors = only_oversized
        .validate_all_fields(30)
        .expect_err("one oversized listener must reject the whole snapshot");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("partial listener set"))
    );
}

#[test]
fn native_normalization_preserves_inconsistent_listener_hostname_claims_for_rejection() {
    let mut config = GatewayConfig {
        frontend_tls_certificate_sources: ["a.example.com", "b.example.com"]
            .into_iter()
            .map(|hostname| FrontendTlsCertificateSource {
                namespace: "ferrum".to_string(),
                gateway: "edge".to_string(),
                listener: "https".to_string(),
                hostname: Some(hostname.to_string()),
                cert_path: "/certs/shared.crt".to_string(),
                key_path: "/certs/shared.key".to_string(),
                ..Default::default()
            })
            .collect(),
        ..GatewayConfig::default()
    };

    config.normalize_fields();

    assert_eq!(
        config.frontend_tls_certificate_sources.len(),
        2,
        "normalization must not erase a contradictory listener hostname claim before the runtime rejects it"
    );
}

#[test]
fn namespace_filter_retains_the_whole_owning_namespace_set() {
    let mut config = translate(&[
        gateway(
            "ferrum",
            "edge",
            vec![https_listener("https", 443, None, &["cert-a", "cert-b"])],
        ),
        tls_secret("cert-a", "ferrum"),
        tls_secret("cert-b", "ferrum"),
    ])
    .config;
    config.frontend_tls_certificate_sources.push(
        ferrum_edge::config::types::FrontendTlsCertificateSource {
            namespace: "other".to_string(),
            gateway: "foreign".to_string(),
            listener: "https".to_string(),
            hostname: Some("foreign.example.com".to_string()),
            cert_path: "k8s://other/foreign#tls.crt".to_string(),
            key_path: "k8s://other/foreign#tls.key".to_string(),
            default_certificate: true,
        },
    );

    let removed = config.filter_frontend_tls_to_namespace("ferrum");

    assert_eq!(removed, 1);
    assert_eq!(config.frontend_tls_certificate_sources.len(), 2);
    assert!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .all(|source| source.namespace == "ferrum"),
        "a data plane must never observe another namespace's certificate"
    );
    assert_eq!(
        config
            .frontend_tls_certificate_sources
            .iter()
            .filter(|source| source.default_certificate)
            .count(),
        1,
        "the fallback marker is re-derived within the retained set"
    );
}

#[test]
fn namespace_filter_withdraws_a_foreign_owned_fallback() {
    let mut config = GatewayConfig {
        frontend_tls_cert_path: Some("k8s://other/foreign#tls.crt".to_string()),
        frontend_tls_key_path: Some("k8s://other/foreign#tls.key".to_string()),
        frontend_tls_source_namespace: Some("other".to_string()),
        ..GatewayConfig::default()
    };

    let removed = config.filter_frontend_tls_to_namespace("ferrum");

    assert_eq!(removed, 1);
    assert_eq!(config.frontend_tls_cert_path, None);
    assert_eq!(config.frontend_tls_key_path, None);
    assert_eq!(config.frontend_tls_source_namespace, None);
}

#[test]
fn namespace_filter_leaves_operator_material_alone() {
    let mut config = GatewayConfig {
        frontend_tls_cert_path: Some("/etc/ferrum/server.crt".to_string()),
        frontend_tls_key_path: Some("/etc/ferrum/server.key".to_string()),
        ..GatewayConfig::default()
    };

    assert_eq!(config.filter_frontend_tls_to_namespace("ferrum"), 0);
    assert_eq!(
        config.frontend_tls_cert_path.as_deref(),
        Some("/etc/ferrum/server.crt"),
        "material with no owning Gateway namespace is the operator's, not a tenant's"
    );
}
