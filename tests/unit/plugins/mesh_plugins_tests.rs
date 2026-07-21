use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{BackendScheme, Proxy};
use ferrum_edge::identity::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, ConditionMatch, MeshConfig, MeshPolicy, MeshRule, MeshService, PolicyAction,
    PolicyScope, PrincipalMatch, RequestMatch, ServicePort, ServiceTargetPort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::request_transformer::RequestTransformer;
use ferrum_edge::plugins::{
    Plugin, PluginFailurePolicy, PluginResult, RequestContext, StreamConnectionContext,
    available_plugins, create_plugin, plugin_failure_policy,
};
use serde_json::json;

fn allow_client_policy(action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: "client-policy".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/client".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

fn allow_ztunnel_policy() -> MeshPolicy {
    MeshPolicy {
        name: "ztunnel-policy".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/ztunnel".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn allow_host_policy(host: &str) -> MeshPolicy {
    MeshPolicy {
        name: "host-policy".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            from: Vec::new(),
            to: vec![RequestMatch {
                hosts: vec![host.to_string()],
                ..RequestMatch::default()
            }],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

fn request_context(source: Option<&str>) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    ctx.peer_spiffe_id = source.map(|id| SpiffeId::new(id).expect("valid spiffe id"));
    ctx
}

fn hbone_relay_request_context(
    peer: &str,
    baggage: Option<&str>,
    backend_host: &str,
    backend_port: u16,
) -> RequestContext {
    let mut ctx = request_context(Some(peer));
    ctx.method = "CONNECT".to_string();
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    if let Some(baggage) = baggage {
        ctx.headers
            .insert("baggage".to_string(), baggage.to_string());
    }
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "default",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": backend_host,
            "backend_port": backend_port
        }))
        .expect("relay proxy"),
    ));
    ctx
}

fn ambient_udp_request_context(peer: &str, baggage: Option<&str>) -> RequestContext {
    let mut ctx = hbone_relay_request_context(peer, baggage, "10.0.0.20", 53);
    ctx.metadata
        .insert("hbone_datagram".to_string(), "udp".to_string());
    ctx
}

fn service_waypoint_byte_stream_request_context(
    peer: &str,
    baggage: Option<&str>,
    backend_host: &str,
) -> RequestContext {
    hbone_relay_request_context(peer, baggage, backend_host, 8080)
}

fn ambient_udp_source_scoping_slice() -> MeshSlice {
    let workload = Workload {
        spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "api".to_string())]),
            namespace: None,
        },
        service_name: "api".to_string(),
        addresses: vec!["10.0.0.20".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("client".to_string()),
        pod_uid: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    MeshSlice {
        namespace: "default".to_string(),
        mesh_policies: vec![
            policy_with_scope(
                "api-deny",
                PolicyScope::WorkloadSelector {
                    selector: WorkloadSelector {
                        labels: HashMap::from([("app".to_string(), "api".to_string())]),
                        namespace: Some("default".to_string()),
                    },
                },
                PolicyAction::Deny,
            ),
            policy_with_scope("mesh-allow", PolicyScope::MeshWide, PolicyAction::Allow),
        ],
        workloads: vec![workload.clone()],
        ambient_udp_source_workloads: vec![workload],
        ..MeshSlice::default()
    }
}

fn stream_context() -> StreamConnectionContext {
    StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        None,
        15443,
        BackendScheme::Tcps,
        Arc::new(ConsumerIndex::new(&[])),
    )
}

#[test]
fn mesh_config_normalize_lowercases_policy_hosts() {
    let mut mesh = MeshConfig {
        mesh_policies: vec![allow_host_policy("Api.Example.Com")],
        ..MeshConfig::default()
    };

    mesh.normalize();

    assert_eq!(
        mesh.mesh_policies[0].rules[0].to[0].hosts,
        vec!["api.example.com"]
    );
}

#[test]
fn mesh_plugins_are_registered() {
    let available = available_plugins();
    assert!(available.contains(&"mesh_authz"));
    assert!(available.contains(&"mesh_outbound_registry"));
    assert!(available.contains(&"workload_metrics"));
    assert_eq!(
        plugin_failure_policy("mesh_authz"),
        Some(PluginFailurePolicy::FailClosed)
    );
    assert_eq!(
        plugin_failure_policy("mesh_outbound_registry"),
        Some(PluginFailurePolicy::FailClosed)
    );
    assert!(create_plugin("mesh_authz", &json!({})).unwrap().is_some());
    assert!(
        create_plugin("mesh_outbound_registry", &json!({"registry": []}))
            .unwrap()
            .is_some()
    );
    assert!(
        create_plugin("workload_metrics", &json!({}))
            .unwrap()
            .is_some()
    );
}

#[test]
fn mesh_outbound_registry_rejects_zero_listen_port_via_create_plugin() {
    // Match on Err so we never require Debug on `Arc<dyn Plugin>` (Ok arm).
    let err = match create_plugin(
        "mesh_outbound_registry",
        &json!({
            "registry": ["reviews.svc"],
            "outbound_listen_ports": [0],
        }),
    ) {
        Ok(_) => panic!("port 0 must fail closed at construction"),
        Err(err) => err,
    };
    assert!(
        err.contains("outbound_listen_ports"),
        "unexpected error: {err}"
    );
}

#[test]
fn mesh_outbound_registry_metric_contract_matches_docs_and_help() {
    // Keep operator docs, OpenAPI wording, and the exported HELP text aligned
    // on the intentional bounded host buckets (not per-destination admits).
    let configuration = include_str!("../../../docs/configuration.md");
    let mesh = include_str!("../../../docs/mesh.md");
    let plugins = include_str!("../../../docs/plugins.md");
    for doc in [configuration, mesh, plugins] {
        assert!(doc.contains("<admit_explicit>"));
        assert!(doc.contains("<admit_wildcard>"));
        assert!(doc.contains("<denied>"));
        assert!(
            !doc.contains("actual destination only for `admit`")
                && !doc.contains("uses the actual destination as the `host` label"),
            "docs must not claim per-destination admit host labels"
        );
    }

    // Force the series into the scrape output so HELP is rendered.
    ferrum_edge::plugins::prometheus_metrics::global_registry()
        .record_mesh_outbound_registry_decision("metric-contract-ns", "<admit_explicit>", "admit");
    let rendered = ferrum_edge::plugins::prometheus_metrics::global_registry().render_uncached();
    assert!(
        rendered.contains(
            "# HELP ferrum_mesh_outbound_registry_decisions_total Mesh outbound registry decisions with bounded host buckets (<admit_explicit>, <admit_wildcard>, <denied>)."
        ),
        "HELP must name the bounded host buckets; got:\n{rendered}"
    );
}

#[test]
fn mesh_authz_rejects_namespace_scoped_direct_policy_without_namespace() {
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-deny",
            PolicyScope::Namespace { namespace: "default".to_string() },
            PolicyAction::Deny,
        )]
    })) {
        Ok(_) => panic!("namespace-scoped direct policy without proxy namespace must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("namespace scope"));
    assert!(err.contains("proxy namespace"));
}

#[test]
fn mesh_authz_rejects_label_selector_direct_policy_without_labels() {
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: None,
    };
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "app-deny",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Deny,
        )],
        "namespace": "default",
    })) {
        Ok(_) => panic!("label-scoped direct policy without proxy labels must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("workload selector with labels"));
    assert!(err.contains("proxy labels"));
}

#[test]
fn mesh_authz_rejects_invalid_direct_source_ip_block() {
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "bad-cidr",
            "namespace": "default",
            "scope": { "kind": "workload_selector", "selector": {} },
            "rules": [{
                "action": "deny",
                "source_negation": { "ip_blocks": ["10.0.0.0/40"] },
                "never_matches": false
            }]
        }],
    })) {
        Ok(_) => panic!("direct mesh_policies with malformed ipBlocks must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("10.0.0.0/40"), "error should name CIDR: {err}");
}

#[test]
fn mesh_authz_rejects_invalid_mesh_slice_source_ip_block() {
    let err = match MeshAuthz::new(&json!({
        "mesh_slice": {
            "namespace": "default",
            "mesh_policies": [{
                "name": "bad-cidr",
                "namespace": "default",
                "scope": { "kind": "workload_selector", "selector": {} },
                "rules": [{
                    "action": "deny",
                    "source_negation": { "not_remote_ip_blocks": ["not-a-cidr"] },
                    "never_matches": false
                }]
            }]
        },
    })) {
        Ok(_) => panic!("mesh_slice with malformed notRemoteIpBlocks must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("not-a-cidr"), "error should name CIDR: {err}");
}

#[test]
fn mesh_authz_rejects_unsupported_direct_when_key() {
    let mut policy = allow_client_policy(PolicyAction::Deny);
    policy.rules[0].when.push(ConditionMatch {
        key: "destination.labels[app]".to_string(),
        values: vec!["payments".to_string()],
        not_values: Vec::new(),
    });

    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy],
    })) {
        Ok(_) => panic!("direct mesh_policies with unsupported when key must fail closed"),
        Err(err) => err,
    };

    assert!(
        err.contains("destination.labels[app]"),
        "error should name unsupported key: {err}"
    );
    assert!(
        err.contains("unsupported"),
        "error should say unsupported: {err}"
    );
}

#[test]
fn mesh_authz_rejects_direct_when_condition_without_values() {
    let mut policy = allow_client_policy(PolicyAction::Deny);
    policy.rules[0].when.push(ConditionMatch {
        key: "connection.sni".to_string(),
        values: Vec::new(),
        not_values: Vec::new(),
    });

    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy],
    })) {
        Ok(_) => panic!("direct mesh_policies with empty when condition must fail closed"),
        Err(err) => err,
    };

    assert!(err.contains("connection.sni"));
    assert!(err.contains("values or notValues"));
}

#[test]
fn mesh_authz_rejects_invalid_direct_when_ip_block() {
    let mut policy = allow_client_policy(PolicyAction::Deny);
    policy.rules[0].when.push(ConditionMatch {
        key: "source.ip".to_string(),
        values: vec!["10.0.0.0/40".to_string()],
        not_values: Vec::new(),
    });

    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [policy],
    })) {
        Ok(_) => panic!("direct mesh_policies with malformed when source.ip must fail closed"),
        Err(err) => err,
    };

    assert!(
        err.contains("source.ip"),
        "error should name condition: {err}"
    );
    assert!(err.contains("values"), "error should name field: {err}");
    assert!(err.contains("10.0.0.0/40"), "error should name CIDR: {err}");
}

#[tokio::test]
async fn mesh_authz_stream_connection_sni_denies_matching_sni() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "deny-admin-sni",
            "namespace": "default",
            "scope": {"kind": "mesh_wide"},
            "rules": [{
                "when": [{
                    "key": "connection.sni",
                    "values": ["admin.mesh.internal"]
                }],
                "action": "deny"
            }]
        }]
    }))
    .expect("plugin config");

    let mut blocked = stream_context();
    blocked.sni_hostname = Some("admin.mesh.internal".to_string());
    assert!(matches!(
        plugin.on_stream_connect(&mut blocked).await,
        PluginResult::Reject { .. }
    ));

    let mut admitted = stream_context();
    admitted.sni_hostname = Some("public.mesh.internal".to_string());
    assert!(matches!(
        plugin.on_stream_connect(&mut admitted).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn mesh_authz_allows_matching_spiffe_identity() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_denies_non_matching_identity_when_allow_policy_exists() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/other"));

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("Mesh authorization denied"));
        }
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_reads_hbone_baggage_source_identity() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_reads_materialized_hbone_baggage_source_identity() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_ignores_hbone_baggage_from_untrusted_assertor() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/other"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    // The peer (sa/client) is not a trusted assertor — the baggage's claim of
    // sa/other must be dropped and surfaced through transaction-log metadata
    // so operators can detect impersonation attempts.
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage")
            .map(String::as_str),
        Some("untrusted_assertor")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.untrusted_assertor")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn mesh_authz_ambient_udp_applies_scope_for_validated_source_pod() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": ambient_udp_source_scoping_slice(),
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(
            "source.principal=spiffe://cluster.local/ns/default/sa/client,source.pod_uid=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "selector-scoped DENY for the attributed pod must apply, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("api-deny")
    );
}

#[tokio::test]
async fn mesh_authz_ambient_udp_retains_identical_duplicate_pod_scopes() {
    let mut slice = ambient_udp_source_scoping_slice();
    let mut second_projection = slice.ambient_udp_source_workloads[0].clone();
    second_projection.service_name = "api-alias".to_string();
    slice.ambient_udp_source_workloads.push(second_projection);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(
            "source.principal=spiffe://cluster.local/ns/default/sa/client,source.pod_uid=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "one pod projected through multiple Services must retain its scoped policy, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("api-deny")
    );
}

#[tokio::test]
async fn mesh_authz_ambient_udp_suppresses_conflicting_duplicate_pod_scopes() {
    let mut slice = ambient_udp_source_scoping_slice();
    let mut stale_principal_deny = allow_client_policy(PolicyAction::Deny);
    stale_principal_deny.name = "stale-principal-deny".to_string();
    stale_principal_deny.scope = PolicyScope::MeshWide;
    slice.mesh_policies.push(stale_principal_deny);
    let mut conflicting = slice.ambient_udp_source_workloads[0].clone();
    conflicting.selector.labels = HashMap::from([("app".to_string(), "other".to_string())]);
    slice.ambient_udp_source_workloads.push(conflicting);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(
            "source.principal=spiffe://cluster.local/ns/default/sa/client,source.pod_uid=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "conflicting pod evidence must use the gateway peer for mesh-wide evaluation, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_udp_source_scope")
            .map(String::as_str),
        Some("pod_not_in_slice")
    );
}

#[tokio::test]
async fn mesh_authz_ambient_udp_missing_or_invalid_pod_evidence_uses_gateway_principal() {
    let mut slice = ambient_udp_source_scoping_slice();
    let mut stale_principal_deny = allow_client_policy(PolicyAction::Deny);
    stale_principal_deny.name = "stale-principal-deny".to_string();
    stale_principal_deny.scope = PolicyScope::MeshWide;
    slice.mesh_policies.push(stale_principal_deny);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    for baggage in [
        "source.principal=spiffe://cluster.local/ns/default/sa/client",
        "source.principal=spiffe://cluster.local/ns/default/sa/client,source.pod_uid=not-a-uid",
    ] {
        let mut ctx = ambient_udp_request_context(
            "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
            Some(baggage),
        );

        let result = plugin.authorize(&mut ctx).await;

        assert!(
            matches!(result, PluginResult::Continue),
            "unbound pod evidence must use the gateway peer for mesh-wide evaluation, got {result:?}"
        );
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.ignored_udp_source_scope")
                .map(String::as_str),
            Some("missing_or_invalid_pod_uid")
        );
    }
}

#[tokio::test]
async fn mesh_authz_ambient_udp_untrusted_stamp_cannot_activate_scoped_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": ambient_udp_source_scoping_slice(),
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/default/sa/untrusted",
        Some(
            "source.principal=spiffe://cluster.local/ns/default/sa/client,source.pod_uid=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "untrusted stamp must fall back to mesh-wide-only evaluation, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.untrusted_assertor")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn mesh_authz_ambient_udp_rejects_principal_pod_mismatch_as_scope_evidence() {
    let mut slice = ambient_udp_source_scoping_slice();
    let mut stale_principal_deny = allow_client_policy(PolicyAction::Deny);
    stale_principal_deny.name = "stale-principal-deny".to_string();
    stale_principal_deny.scope = PolicyScope::MeshWide;
    stale_principal_deny.rules[0].from[0].spiffe_id_pattern =
        Some("spiffe://cluster.local/ns/default/sa/other".to_string());
    slice.mesh_policies.push(stale_principal_deny);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(
            "source.principal=spiffe://cluster.local/ns/default/sa/other,source.pod_uid=6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "mismatched evidence must discard the asserted principal before mesh-wide evaluation, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_udp_source_scope")
            .map(String::as_str),
        Some("principal_pod_mismatch")
    );

    let metrics = WorkloadMetrics::new(&json!({})).expect("metrics config");
    let mut headers = std::mem::take(&mut ctx.headers);
    let metrics_result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(metrics_result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/ferrum-system/sa/ztunnel"),
        "downstream telemetry must use the authenticated peer after authz rejects the evidence"
    );
    assert_eq!(
        ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
        Some("principal_pod_mismatch")
    );
}

/// A cross-namespace Ambient UDP slice: the terminating relay's destination
/// namespace (`slice.namespace`) is `svc-ns`, while the validated source pod
/// lives in `client-ns`. This isolates the two policy arms of the UDP
/// authorization union — a `Namespace{svc-ns}` policy is DESTINATION-scoped only
/// and a `Namespace{client-ns}` policy is SOURCE-scoped only — so a test can
/// prove each arm is evaluated independently.
fn ambient_udp_cross_namespace_slice(policies: Vec<MeshPolicy>) -> MeshSlice {
    let client = Workload {
        spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/client-ns/sa/client").expect("spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "client".to_string())]),
            namespace: None,
        },
        service_name: "client".to_string(),
        addresses: vec!["10.0.1.20".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: "client-ns".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("client".to_string()),
        pod_uid: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    MeshSlice {
        // Destination workload identity the relay terminates for. The
        // construction-time retain filters `mesh_policies` to those applicable
        // to THIS namespace/labels, exactly as normal (non-UDP) inbound HBONE
        // evaluates.
        namespace: "svc-ns".to_string(),
        mesh_policies: policies,
        workloads: vec![client.clone()],
        ambient_udp_source_workloads: vec![client],
        ..MeshSlice::default()
    }
}

fn ambient_udp_service_waypoint_slice(policies: Vec<MeshPolicy>) -> MeshSlice {
    let source = Workload {
        spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/client-ns/sa/client")
            .expect("source spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "client".to_string())]),
            namespace: None,
        },
        service_name: "client".to_string(),
        addresses: vec!["10.0.1.20".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("source trust domain"),
        namespace: "client-ns".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("client".to_string()),
        pod_uid: Some("6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    let destination = Workload {
        spiffe_id: SpiffeId::new("spiffe://cluster.local/ns/svc-ns/sa/reviews")
            .expect("destination spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
            namespace: None,
        },
        service_name: "reviews".to_string(),
        addresses: vec!["10.0.2.30".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("destination trust domain"),
        namespace: "svc-ns".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("reviews".to_string()),
        pod_uid: Some("7ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string()),
        node_waypoint: None,
        remote_provenance: false,
    };
    MeshSlice {
        namespace: "waypoint-ns".to_string(),
        waypoint_name: Some("reviews-waypoint".to_string()),
        mesh_policies: policies,
        workloads: vec![destination.clone()],
        ambient_udp_source_workloads: vec![source],
        services: vec![MeshService {
            name: "reviews".to_string(),
            namespace: "svc-ns".to_string(),
            ports: vec![
                ServicePort {
                    port: 53,
                    protocol: AppProtocol::Udp,
                    name: Some("dns".to_string()),
                    target_port: None,
                },
                ServicePort {
                    port: 8080,
                    protocol: AppProtocol::Tcp,
                    name: Some("tcp".to_string()),
                    target_port: None,
                },
            ],
            workloads: vec![WorkloadRef {
                spiffe_id: destination.spiffe_id,
            }],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        ..MeshSlice::default()
    }
}

const AMBIENT_UDP_CLIENT_BAGGAGE: &str = "source.principal=spiffe://cluster.local/ns/client-ns/sa/client,\
     source.pod_uid=6ba7b810-9dad-11d1-80b4-00c04fd430c8";

/// A `from.principal`-keyed ALLOW that only matches the given SPIFFE id, with an
/// arbitrary policy scope. Used to build applicable-but-unmatched vs. matched
/// ALLOW policies for the union aggregation test.
fn principal_scoped_policy(
    name: &str,
    scope: PolicyScope,
    principal: &str,
    action: PolicyAction,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

/// Byte-stream HBONE must use the same exact ServiceWaypoint destination scope
/// resolution as datagram HBONE. The waypoint namespace is deliberately
/// different from the protected Service namespace so the construction-time
/// retain drops this policy from the ordinary slice policy set.
#[tokio::test]
async fn mesh_authz_service_waypoint_byte_stream_resolves_destination_namespace_deny() {
    let slice = ambient_udp_service_waypoint_slice(vec![policy_with_scope(
        "dest-deny-all",
        PolicyScope::Namespace {
            namespace: "svc-ns".to_string(),
        },
        PolicyAction::Deny,
    )]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
        "10.0.2.30",
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "destination namespace DENY must block byte-stream HBONE, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("dest-deny-all")
    );
}

/// An applicable destination ALLOW must admit only a matching source and raise
/// the implicit-deny floor for every other authenticated peer. The successful
/// decision also binds later route dispatch to the exact authorized backend.
#[tokio::test]
async fn mesh_authz_service_waypoint_byte_stream_enforces_destination_allow() {
    let slice = ambient_udp_service_waypoint_slice(vec![principal_scoped_policy(
        "dest-allow-client",
        PolicyScope::Namespace {
            namespace: "svc-ns".to_string(),
        },
        "spiffe://cluster.local/ns/client-ns/sa/client",
        PolicyAction::Allow,
    )]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");

    let mut allowed = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
        "10.0.2.30",
    );
    let allowed_result = plugin.authorize(&mut allowed).await;
    assert!(
        matches!(allowed_result, PluginResult::Continue),
        "matching destination ALLOW should admit byte-stream HBONE, got {allowed_result:?}"
    );
    assert_eq!(
        allowed
            .metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("10.0.2.30|8080"),
        "route dispatch must remain bound to the authorized byte-stream destination"
    );

    let mut denied = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some("source.principal=spiffe://cluster.local/ns/client-ns/sa/other"),
        "10.0.2.30",
    );
    let denied_result = plugin.authorize(&mut denied).await;
    assert!(
        matches!(
            denied_result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "non-matching source must hit destination ALLOW implicit-deny, got {denied_result:?}"
    );
    assert_eq!(
        denied
            .metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_service_waypoint_byte_stream_uses_exact_destination_workload_scope() {
    let destination_selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        namespace: Some("svc-ns".to_string()),
    };
    let mut slice = ambient_udp_service_waypoint_slice(vec![policy_with_scope(
        "reviews-only-deny",
        PolicyScope::WorkloadSelector {
            selector: destination_selector,
        },
        PolicyAction::Deny,
    )]);
    let mut other_destination = slice.workloads[0].clone();
    other_destination.spiffe_id =
        SpiffeId::new("spiffe://cluster.local/ns/svc-ns/sa/ratings").expect("other spiffe");
    other_destination.selector.labels = HashMap::from([("app".to_string(), "ratings".to_string())]);
    other_destination.service_account = Some("ratings".to_string());
    other_destination.addresses = vec!["10.0.2.31".to_string()];
    other_destination.pod_uid = None;
    slice.services[0].workloads.push(WorkloadRef {
        spiffe_id: other_destination.spiffe_id.clone(),
    });
    slice.workloads.push(other_destination);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");

    let mut reviews = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
        "10.0.2.30",
    );
    let reviews_result = plugin.authorize(&mut reviews).await;
    assert!(
        matches!(
            reviews_result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "selector DENY must apply to the selected reviews workload, got {reviews_result:?}"
    );

    let mut ratings = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
        "10.0.2.31",
    );
    let ratings_result = plugin.authorize(&mut ratings).await;
    assert!(
        matches!(ratings_result, PluginResult::Continue),
        "selector DENY for a sibling workload must not affect ratings, got {ratings_result:?}"
    );
    assert_eq!(
        ratings
            .metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("10.0.2.31|8080")
    );
}

#[tokio::test]
async fn mesh_authz_service_waypoint_byte_stream_missing_destination_scope_fails_closed() {
    let slice = ambient_udp_service_waypoint_slice(vec![policy_with_scope(
        "mesh-allow",
        PolicyScope::MeshWide,
        PolicyAction::Allow,
    )]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
        "10.0.2.99",
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.destination_scope_missing")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("destination_scope_missing")
    );
}

#[tokio::test]
async fn mesh_authz_service_waypoint_byte_stream_materializes_destination_condition_inputs() {
    let mut conditional_deny = policy_with_scope(
        "blocked-team-deny",
        PolicyScope::Namespace {
            namespace: "svc-ns".to_string(),
        },
        PolicyAction::Deny,
    );
    conditional_deny.rules[0].when.push(ConditionMatch {
        key: "request.headers[x-team]".to_string(),
        values: vec!["blocked".to_string()],
        not_values: Vec::new(),
    });
    conditional_deny.rules[0].to.push(RequestMatch {
        headers: HashMap::from([("x-route".to_string(), "blocked".to_string())]),
        ..RequestMatch::default()
    });
    let slice = ambient_udp_service_waypoint_slice(vec![conditional_deny]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = service_waypoint_byte_stream_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
        "10.0.2.30",
    );
    ctx.headers
        .insert("x-team".to_string(), "blocked".to_string());
    ctx.headers
        .insert("x-route".to_string(), "blocked".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "destination policy request and condition headers must be built from the relay superset, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("blocked-team-deny")
    );
}

/// (a) A DESTINATION-namespace DENY-all must block a `udp` CONNECT even when the
/// validated source pod's own namespace-scoped ALLOW would otherwise permit it.
/// Before the union fix the branch evaluated ONLY source-scoped policies, so the
/// destination DENY (scoped to a different namespace than the source pod) was
/// filtered out and the request fell through to the source ALLOW.
#[tokio::test]
async fn mesh_authz_ambient_udp_destination_namespace_deny_blocks_source_allowed_connect() {
    let slice = ambient_udp_cross_namespace_slice(vec![
        // Destination-only: applies to svc-ns (the slice namespace), not client-ns.
        policy_with_scope(
            "dest-deny-all",
            PolicyScope::Namespace {
                namespace: "svc-ns".to_string(),
            },
            PolicyAction::Deny,
        ),
        // Source-only: applies to the client pod's namespace, not svc-ns.
        policy_with_scope(
            "client-allow",
            PolicyScope::Namespace {
                namespace: "client-ns".to_string(),
            },
            PolicyAction::Allow,
        ),
    ]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "destination-namespace DENY-all must run for a udp CONNECT, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("dest-deny-all")
    );
}

/// ServiceWaypoint's slice namespace is the waypoint's own namespace, not the
/// namespace of the Service it protects. Destination policy resolution must use
/// the CONNECT authority/backend workload scope or a service-namespace DENY is
/// lost after the construction-time waypoint-identity retain.
#[tokio::test]
async fn mesh_authz_service_waypoint_udp_resolves_destination_service_scope() {
    let slice = ambient_udp_service_waypoint_slice(vec![
        policy_with_scope(
            "dest-deny-all",
            PolicyScope::Namespace {
                namespace: "svc-ns".to_string(),
            },
            PolicyAction::Deny,
        ),
        policy_with_scope(
            "client-allow",
            PolicyScope::Namespace {
                namespace: "client-ns".to_string(),
            },
            PolicyAction::Allow,
        ),
    ]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
    );
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.2.30",
            "backend_port": 53
        }))
        .expect("service-waypoint relay proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "destination Service DENY must run at a cross-namespace waypoint, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("dest-deny-all")
    );
}

#[tokio::test]
async fn mesh_authz_service_waypoint_udp_uses_exact_destination_workload_scope() {
    let destination_selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        namespace: Some("svc-ns".to_string()),
    };
    let mut slice = ambient_udp_service_waypoint_slice(vec![policy_with_scope(
        "reviews-only-deny",
        PolicyScope::WorkloadSelector {
            selector: destination_selector,
        },
        PolicyAction::Deny,
    )]);
    let mut other_destination = slice.workloads[0].clone();
    other_destination.spiffe_id =
        SpiffeId::new("spiffe://cluster.local/ns/svc-ns/sa/ratings").expect("other spiffe");
    other_destination.selector.labels = HashMap::from([("app".to_string(), "ratings".to_string())]);
    other_destination.service_account = Some("ratings".to_string());
    other_destination.addresses = vec!["10.0.2.31".to_string()];
    other_destination.pod_uid = None;
    slice.services[0].workloads.push(WorkloadRef {
        spiffe_id: other_destination.spiffe_id.clone(),
    });
    slice.workloads.push(other_destination);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
    );
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.2.31",
            "backend_port": 53
        }))
        .expect("service-waypoint relay proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "selector DENY for a sibling backend must not apply to the matched backend, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("10.0.2.31|53"),
        "ServiceWaypoint UDP must bind later route overrides to the authorized backend"
    );
}

#[tokio::test]
async fn mesh_authz_service_waypoint_udp_missing_destination_scope_fails_closed() {
    let slice = ambient_udp_service_waypoint_slice(vec![policy_with_scope(
        "client-allow",
        PolicyScope::Namespace {
            namespace: "client-ns".to_string(),
        },
        PolicyAction::Allow,
    )]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 403,
            ..
        }
    ));
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("destination_scope_missing")
    );
}

/// (b) A SOURCE-scoped DENY still blocks after the union: bringing destination
/// policies in must not weaken the source-scoped enforcement this PR added.
#[tokio::test]
async fn mesh_authz_ambient_udp_source_scoped_deny_still_blocks_after_union() {
    let slice = ambient_udp_cross_namespace_slice(vec![
        // Destination-only ALLOW-all (matches everything for the destination).
        policy_with_scope(
            "dest-allow-all",
            PolicyScope::Namespace {
                namespace: "svc-ns".to_string(),
            },
            PolicyAction::Allow,
        ),
        // Source-only DENY-all keyed to the client pod's namespace.
        policy_with_scope(
            "client-deny",
            PolicyScope::Namespace {
                namespace: "client-ns".to_string(),
            },
            PolicyAction::Deny,
        ),
    ]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "source-scoped DENY must still deny under the union, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("client-deny")
    );
}

/// (c) ALLOW aggregation across the union follows Istio "if any applicable ALLOW
/// exists, at least one must match" semantics computed over the COMBINED set —
/// not two independent decisions. A destination-scoped ALLOW that is applicable
/// but does not match (`from.principal` = someone else) sets `saw_allow`, and a
/// source-scoped ALLOW that DOES match the client satisfies it, so the request is
/// allowed. A broken two-decision combination would let the destination arm alone
/// resolve to implicit-deny and reject.
#[tokio::test]
async fn mesh_authz_ambient_udp_allow_aggregation_spans_union() {
    let slice = ambient_udp_cross_namespace_slice(vec![
        // Destination-scoped ALLOW that is applicable (svc-ns) but never matches
        // this client principal — on its own it would implicit-deny.
        principal_scoped_policy(
            "dest-allow-other",
            PolicyScope::Namespace {
                namespace: "svc-ns".to_string(),
            },
            "spiffe://cluster.local/ns/svc-ns/sa/other",
            PolicyAction::Allow,
        ),
        // Source-scoped ALLOW that matches the client principal.
        principal_scoped_policy(
            "client-allow",
            PolicyScope::Namespace {
                namespace: "client-ns".to_string(),
            },
            "spiffe://cluster.local/ns/client-ns/sa/client",
            PolicyAction::Allow,
        ),
    ]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some(AMBIENT_UDP_CLIENT_BAGGAGE),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "a matching source ALLOW must satisfy the union's ALLOW aggregation, got {result:?}"
    );
}

/// (d) Absent source evidence must still fail closed to mesh-wide + DESTINATION
/// policies. A destination-namespace DENY must run even when no source pod scope
/// can be resolved (no `source.pod_uid` in baggage), instead of silently allowing.
#[tokio::test]
async fn mesh_authz_ambient_udp_absent_source_evidence_still_applies_destination_deny() {
    let slice = ambient_udp_cross_namespace_slice(vec![policy_with_scope(
        "dest-deny-all",
        PolicyScope::Namespace {
            namespace: "svc-ns".to_string(),
        },
        PolicyAction::Deny,
    )]);
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "ambient_udp_source_scoping": true,
    }))
    .expect("plugin config");
    // Principal present but no pod_uid → source scope unresolved, evidence falls
    // back to the authenticated gateway peer for mesh-wide-only source scoping.
    let mut ctx = ambient_udp_request_context(
        "spiffe://cluster.local/ns/ferrum-system/sa/ztunnel",
        Some("source.principal=spiffe://cluster.local/ns/client-ns/sa/client"),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "destination DENY must run even with absent source pod evidence, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("dest-deny-all")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_udp_source_scope")
            .map(String::as_str),
        Some("missing_or_invalid_pod_uid")
    );
}

#[tokio::test]
async fn mesh_authz_default_trusts_waypoint_service_account() {
    // The default trusted_hbone_assertors list includes both ztunnel and
    // waypoint — a waypoint peer asserting baggage on behalf of a workload
    // must be honored, with no ignored-baggage diagnostic.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/waypoint"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
}

#[tokio::test]
async fn mesh_authz_trusted_hbone_assertors_accepts_custom_service_account() {
    // Operators with Gateway-managed waypoints (SA names like
    // "default-waypoint") configure the allow-list to cover their custom
    // names. The configured SA must be treated as a trusted assertor.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trusted_hbone_assertors": ["default-waypoint"],
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/default-waypoint"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
}

#[tokio::test]
async fn mesh_authz_trusted_hbone_assertors_accepts_exact_spiffe_id() {
    // Operators pinning a specific assertor identity supply the full SPIFFE
    // id. Matching is exact — bare SA-name semantics do not apply.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trusted_hbone_assertors": [
            "spiffe://cluster.local/ns/istio-system/sa/ztunnel",
        ],
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/istio-system/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
}

#[tokio::test]
async fn mesh_authz_trusted_hbone_assertors_exact_spiffe_id_rejects_other_trust_domains() {
    // Pinned-by-SPIFFE-id mode must NOT honor an `sa/ztunnel` peer from a
    // different trust domain. Baggage is dropped, peer identity is used, and
    // the policy (which only allows `sa/client`) denies the resulting
    // request. We verify the diagnostic chain end-to-end.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trusted_hbone_assertors": [
            "spiffe://cluster.local/ns/istio-system/sa/ztunnel",
        ],
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/istio-system/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    // Baggage drop + peer-cert fallback + policy mismatch = Reject.
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected Reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.untrusted_assertor")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("untrusted_assertor")
    );
}

#[tokio::test]
async fn mesh_authz_trusted_assertor_honors_trust_domain_alias() {
    // A trusted assertor in an aliased trust domain may still assert a
    // baggage identity from the local trust domain. The trust_domain_aliases
    // check remains in force alongside the trusted-assertor gate.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trust_domain_aliases": ["cluster.local"],
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
}

#[tokio::test]
async fn mesh_authz_empty_trusted_hbone_assertors_drops_all_baggage() {
    // An operator-set empty list locks down baggage rewriting entirely — even
    // ztunnel peers see their baggage dropped, fall back to peer-cert
    // identity, and are subject to the implicit-deny floor when the policy
    // doesn't cover the peer SPIFFE id.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trusted_hbone_assertors": [],
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    // The baggage's `sa/client` would have been allowed if honored, so a
    // Reject proves the baggage was dropped.
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected Reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.untrusted_assertor")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("untrusted_assertor")
    );
}

#[tokio::test]
async fn mesh_authz_untrusted_assertor_without_baggage_is_silent() {
    // An untrusted-but-authenticated HBONE peer that does NOT send a baggage
    // source identity should not trip the diagnostic — there is nothing
    // observable to report. The peer cert identity authorises normally.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
    assert!(
        !ctx.metadata
            .contains_key("mesh_authz.ignored_baggage.untrusted_assertor")
    );
}

#[test]
fn mesh_authz_rejects_trusted_hbone_assertors_non_string_entries() {
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trusted_hbone_assertors": [42],
    })) {
        Ok(_) => panic!("plugin config should fail"),
        Err(err) => err,
    };
    assert!(
        err.contains("trusted_hbone_assertors"),
        "error should mention the field: {err}"
    );
}

#[test]
fn mesh_authz_rejects_trusted_hbone_assertors_invalid_uri_scheme() {
    let err = match MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trusted_hbone_assertors": ["https://cluster.local/ns/x/sa/y"],
    })) {
        Ok(_) => panic!("plugin config should fail"),
        Err(err) => err,
    };
    assert!(
        err.contains("trusted_hbone_assertors"),
        "error should mention the field: {err}"
    );
}

#[tokio::test]
async fn mesh_authz_ignores_hbone_baggage_without_authenticated_peer() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage")
            .map(String::as_str),
        Some("unauthenticated_hbone")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.unauthenticated")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("unauthenticated_baggage")
    );
}

#[tokio::test]
async fn mesh_authz_reads_split_hbone_baggage_headers() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.append(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_denies_percent_encoded_hbone_baggage_mismatch() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    headers.append(
        "baggage",
        "source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fdefault%2Fsa%2Fother"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("Mesh authorization denied"));
        }
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_normalizes_header_policy_keys_at_construction() {
    let mut policy = allow_client_policy(PolicyAction::Allow);
    policy.rules[0].to = vec![RequestMatch {
        headers: HashMap::from([("X-Tenant".to_string(), "prod".to_string())]),
        ..RequestMatch::default()
    }];
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-tenant", "prod".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_collapses_conflicting_header_policy_keys() {
    // Spec change (PR #992 / commit 8cdba9d8): the previous behavior left
    // case-colliding policy header entries verbatim, which made them
    // unmatchable and effectively created a bypass for deny rules
    // expressed with mixed-case keys. Normalization now collapses every
    // header key to lowercase, so a policy carrying both `X-Tenant=prod`
    // and `x-tenant=dev` ends up with a single `x-tenant` entry. HashMap
    // iteration order is unspecified, so either value can survive the
    // collapse — what matters is that the policy is now deterministic for
    // any one process and that authorization evaluates against the
    // collapsed entry rather than against the ambiguous original pair.
    //
    // To keep this test stable, we use the SAME value on both colliding
    // keys so the collapse outcome is the same regardless of which entry
    // wins. The policy then unambiguously matches the request, and the
    // regression guard is that authz still evaluates header rules after
    // case-collapse rather than silently ignoring the rule pair.
    let mut policy = allow_client_policy(PolicyAction::Allow);
    policy.rules[0].to = vec![RequestMatch {
        headers: HashMap::from([
            ("X-Tenant".to_string(), "prod".to_string()),
            ("x-tenant".to_string(), "prod".to_string()),
        ]),
        ..RequestMatch::default()
    }];
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-tenant", "prod".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "post-collapse policy must match a request whose header equals the surviving canonical value, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_ignores_raw_reserved_header_when_materialized_map_filtered() {
    let mut policy = allow_client_policy(PolicyAction::Allow);
    policy.rules[0].when = vec![ConditionMatch {
        key: "request.headers[x-consumer-username]".to_string(),
        values: vec!["admin".to_string()],
        not_values: Vec::new(),
    }];
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-consumer-username",
        "admin".parse().expect("header value"),
    );
    ctx.set_raw_headers(headers);
    ctx.materialize_headers();

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("Mesh authorization denied"));
        }
        other => panic!("expected implicit deny for spoofed reserved header, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_ignores_raw_reserved_path_param_header() {
    let mut policy = allow_client_policy(PolicyAction::Allow);
    policy.rules[0].when = vec![ConditionMatch {
        key: "request.headers[x-path-param-user]".to_string(),
        values: vec!["admin".to_string()],
        not_values: Vec::new(),
    }];
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-path-param-user", "admin".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 403);
            assert!(body.contains("Mesh authorization denied"));
        }
        other => panic!("expected implicit deny for spoofed path-param header, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_skips_header_materialization_without_header_rules() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = http::HeaderMap::new();
    headers.insert("x-unused", "still-raw".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.headers.is_empty());
}

#[tokio::test]
async fn mesh_authz_uses_materialized_host_backfilled_from_authority() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert("host", "api.example.com".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_strips_host_port_before_matching_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert("host", "api.example.com:443".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_preserves_host_policy_authority_port() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com:8443")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "host",
        "api.example.com:8443".parse().expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_rejects_non_matching_host_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_host_policy("api.example.com")]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = http::HeaderMap::new();
    headers.insert("host", "other.example.com".parse().expect("header value"));
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_matches_http_frontend_port_policy() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "port-policy",
            "namespace": "default",
            "scope": {"kind": "mesh_wide"},
            "rules": [{
                "to": [{"ports": [8443]}],
                "action": "allow"
            }]
        }]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.frontend_listen_port = Some(8443);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn workload_metrics_adds_identity_metadata_without_header_changes() {
    let plugin = WorkloadMetrics::new(&json!({
        "node_id": "node-a",
        "topology": "sidecar",
        "namespace": "default",
        "labels": {
            "app": "client",
            "service.istio.io/canonical-name": "client-svc"
        }
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "svc-proxy",
        "name": "payments",
        "namespace": "default",
        "hosts": ["payments.default.svc.cluster.local"],
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture");
    ctx.matched_proxy = Some(Arc::new(proxy));
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(headers.is_empty());
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.namespace")
            .map(String::as_str),
        Some("default")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.destination.service")
            .map(String::as_str),
        Some("payments")
    );
    assert_eq!(
        ctx.metadata.get("mesh.topology").map(String::as_str),
        Some("sidecar")
    );
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("client-svc")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.request_protocol")
            .map(String::as_str),
        Some("http")
    );
}

#[tokio::test]
async fn workload_metrics_reads_hbone_baggage_source_identity() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
}

#[tokio::test]
async fn workload_metrics_marks_mtls_when_http_peer_cert_has_no_spiffe_id() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(None);
    ctx.tls_client_cert_der = Some(Arc::new(vec![0x30, 0x82, 0x01, 0x00]));
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
    assert!(!ctx.metadata.contains_key("mesh.source.principal"));
}

#[tokio::test]
async fn workload_metrics_reads_split_hbone_baggage_headers() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.append(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    raw_headers.append(
        "baggage",
        "destination.principal=spiffe://cluster.local/ns/default/sa/server"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    let mut headers = std::mem::take(&mut ctx.headers);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
}

#[tokio::test]
async fn workload_metrics_reads_forwarded_materialized_hbone_baggage() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut raw_headers = http::HeaderMap::new();
    raw_headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(raw_headers);
    ctx.materialize_headers();
    let mut headers = std::mem::take(&mut ctx.headers);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
}

#[tokio::test]
async fn workload_metrics_ignores_stale_materialized_hbone_baggage() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    );
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("ztunnel")
    );
}

#[tokio::test]
async fn workload_metrics_does_not_trust_hbone_baggage_without_authenticated_peer() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("none")
    );
    assert_eq!(
        ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
        Some("unauthenticated_hbone")
    );
    assert!(!ctx.metadata.contains_key("mesh.source.principal"));
    assert!(!ctx.metadata.contains_key("mesh.source.service_account"));
}

#[tokio::test]
async fn workload_metrics_uses_workload_hint_when_peer_identity_absent() {
    let plugin = WorkloadMetrics::new(&json!({
        "topology": "ambient",
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/api",
        "labels": {
            "app.kubernetes.io/name": "api"
        }
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/grpc+proto".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/api")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.trust_domain")
            .map(String::as_str),
        Some("cluster.local")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.namespace")
            .map(String::as_str),
        Some("default")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("api")
    );
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("api")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.request_protocol")
            .map(String::as_str),
        Some("grpc")
    );
}

#[tokio::test]
async fn mesh_authz_drops_baggage_with_mismatched_trust_domain() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_ztunnel_policy()]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://attacker.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage")
            .map(String::as_str),
        Some("trust_domain_mismatch")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage.trust_domain_mismatch")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn mesh_authz_accepts_baggage_in_aliased_trust_domain() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)],
        "trust_domain_aliases": ["cluster.local"]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("mesh_authz.ignored_baggage"));
}

#[tokio::test]
async fn mesh_authz_hbone_alias_lookup_does_not_require_source_in_slice_workloads() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": {
            "node_id": "node-a",
            "namespace": "default",
            "version": "test",
            "workloads": [],
            "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
        },
        "trust_domain_aliases": ["cluster.local"]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://cluster.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !ctx.metadata.contains_key("mesh_authz.ignored_baggage"),
        "HBONE baggage trust-domain aliasing is independent of slice.workloads"
    );
}

#[tokio::test]
async fn mesh_authz_rejected_baggage_mismatch_records_deny_policy() {
    let plugin = MeshAuthz::new(&json!({
        // Policy only allows the baggage workload identity. After we drop
        // the cross-trust-domain baggage, the peer (ztunnel) identity
        // doesn't match, so this rejects.
        "mesh_policies": [allow_client_policy(PolicyAction::Allow)]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "baggage",
        "source.principal=spiffe://attacker.local/ns/default/sa/client"
            .parse()
            .expect("header value"),
    );
    ctx.set_raw_headers(headers);

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.ignored_baggage")
            .map(String::as_str),
        Some("trust_domain_mismatch")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("trust_domain_mismatch")
    );
}

#[tokio::test]
async fn mesh_authz_rejects_invalid_trust_domain_alias() {
    let result = MeshAuthz::new(&json!({
        "trust_domain_aliases": ["NotLowercase.Test"]
    }));
    let err = match result {
        Ok(_) => panic!("invalid alias should fail construction"),
        Err(e) => e,
    };
    assert!(
        err.contains("NotLowercase.Test"),
        "error should mention bad alias, got: {err}"
    );
}

#[tokio::test]
async fn workload_metrics_drops_baggage_with_mismatched_trust_domain() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://attacker.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/ztunnel")
    );
    assert_eq!(
        ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
        Some("trust_domain_mismatch")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
}

/// A non-assertor peer (an ordinary workload, not ztunnel/waypoint) cannot
/// rewrite the telemetry source identity via forged HBONE baggage — even when
/// the baggage trust domain matches the peer's. The baggage is dropped and the
/// peer-cert identity is used, mirroring `mesh_authz`'s untrusted-assertor gate
/// so dashboards/graph/spans cannot be made to mis-attribute source identity.
#[tokio::test]
async fn workload_metrics_ignores_baggage_from_untrusted_assertor() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    // sa/client is NOT a default trusted assertor (ztunnel/waypoint).
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        // Same trust domain as the peer, so ONLY the assertor gate (not the
        // trust-domain check) can block this forged victim identity.
        "source.principal=spiffe://cluster.local/ns/victim/sa/other".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    // Attribution falls back to the peer cert identity, NOT the forged baggage.
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/client")
    );
    assert_eq!(
        ctx.metadata.get("mesh.ignored_baggage").map(String::as_str),
        Some("untrusted_assertor")
    );
}

/// A custom-configured assertor (matching the peer SA) honors the baggage,
/// confirming the gate is the shared `mesh_authz` allow-list and configurable —
/// not a hardcoded ztunnel/waypoint check.
#[tokio::test]
async fn workload_metrics_honors_baggage_from_configured_assertor() {
    let plugin = WorkloadMetrics::new(&json!({
        "trusted_hbone_assertors": ["client"]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/web/sa/frontend".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/web/sa/frontend")
    );
    assert!(!ctx.metadata.contains_key("mesh.ignored_baggage"));
}

#[tokio::test]
async fn workload_metrics_sampling_zero_records_unsampled() {
    let plugin = WorkloadMetrics::new(&json!({
        "sampling_percentage": 0.0
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("false")
    );
}

#[tokio::test]
async fn workload_metrics_on_stream_connect_adds_source_identity_metadata() {
    let plugin = WorkloadMetrics::new(&json!({
        "node_id": "node-a",
        "topology": "sidecar",
        "labels": {
            "service.istio.io/canonical-name": "client-svc"
        }
    }))
    .expect("plugin config");
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        Some("payments-tcp".to_string()),
        15432,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    ctx.authenticated_identity = Some("spiffe://cluster.local/ns/default/sa/client".to_string());
    ctx.tls_client_cert_der = Some(Arc::new(vec![1, 2, 3]));

    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let metadata = ctx.metadata.expect("stream metadata");
    assert_eq!(
        metadata.get("mesh.source.principal").map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/client")
    );
    assert_eq!(
        metadata.get("mesh.source.namespace").map(String::as_str),
        Some("default")
    );
    assert_eq!(
        metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("client")
    );
    assert_eq!(
        metadata.get("mesh.source.workload").map(String::as_str),
        Some("client-svc")
    );
    assert_eq!(
        metadata
            .get("mesh.connection_security_policy")
            .map(String::as_str),
        Some("mutual_tls")
    );
    assert_eq!(
        metadata.get("mesh.topology").map(String::as_str),
        Some("sidecar")
    );
}

#[tokio::test]
async fn workload_metrics_accepts_baggage_in_aliased_trust_domain() {
    let plugin = WorkloadMetrics::new(&json!({
        "trust_domain_aliases": ["cluster.local"]
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://partner.local/ns/default/sa/ztunnel"));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/client".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/client")
    );
    assert!(!ctx.metadata.contains_key("mesh.ignored_baggage"));
}

#[tokio::test]
async fn workload_metrics_rejects_invalid_trust_domain_alias() {
    let result = WorkloadMetrics::new(&json!({
        "trust_domain_aliases": ["Bad.Trust"]
    }));
    let err = match result {
        Ok(_) => panic!("invalid alias should fail construction"),
        Err(e) => e,
    };
    assert!(
        err.contains("Bad.Trust"),
        "error should mention bad alias, got: {err}"
    );
}

// ── PolicyScope enforcement tests ────────────────────────────────────────────
//
// These tests pin the security-correctness contract that `mesh_authz`
// honors `PolicyScope`. Before this fix, every policy in `slice.mesh_policies`
// applied to every workload regardless of scope, which let a namespace-scoped
// DENY in namespace `A` reject traffic in namespace `B`, and a namespace- /
// workload-scoped ALLOW raise the implicit-deny floor for unrelated proxies.

fn policy_with_scope(name: &str, scope: PolicyScope, action: PolicyAction) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope,
        rules: vec![MeshRule {
            from: Vec::new(),
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action,
        }],
    }
}

#[tokio::test]
async fn mesh_authz_mesh_wide_allow_applies_to_any_workload() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
        "namespace": "billing",
        "labels": {"app": "api"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_allow_does_not_affect_other_namespaces() {
    // Cross-namespace ALLOW must NOT raise `saw_allow` for an unrelated proxy.
    // Pre-fix: this returned Reject{implicit-deny}.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-allow",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Allow,
        )],
        "namespace": "team-b",
        "labels": {},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "namespace-scoped ALLOW in team-a must not implicit-deny team-b traffic, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_allow_applies_in_matching_namespace() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-allow",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Allow,
        )],
        "namespace": "team-a",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    // Allow rule has no `from` — empty principals match anything → matched_allow.
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_deny_only_denies_in_matching_namespace() {
    // DENY in team-a must not deny team-b.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-deny",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Deny,
        )],
        "namespace": "team-b",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "namespace-scoped DENY in team-a must not deny team-b traffic, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_namespace_scoped_deny_denies_in_matching_namespace() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "ns-a-deny",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Deny,
        )],
        "namespace": "team-a",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("expected reject, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("ns-a-deny")
    );
}

#[tokio::test]
async fn mesh_authz_workload_selector_subset_match_applies() {
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: None,
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "labels": {"app": "api", "tier": "frontend"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/api"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_workload_selector_missing_label_does_not_affect_unrelated_workloads() {
    // Selector requires `app=api`; this workload has `app=worker` → policy must
    // NOT apply, so the unrelated proxy continues as if the policy were absent.
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: None,
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "labels": {"app": "worker"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/worker"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "WorkloadSelector ALLOW for app=api must not implicit-deny app=worker, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_workload_selector_empty_labels_matches_any_workload() {
    // Empty labels + no namespace applies to any workload. This test pins the
    // selector contract.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-any-allow",
            PolicyScope::WorkloadSelector { selector: WorkloadSelector::default() },
            PolicyAction::Allow,
        )],
        "namespace": "anything",
        "labels": {"role": "backend"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/anything/sa/anyone"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_workload_selector_namespace_and_labels_combined() {
    // Selector requires both namespace=team-a AND app=api. Proxy is namespace
    // team-a but app=worker → policy must NOT apply.
    let selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "api".to_string())]),
        namespace: Some("team-a".to_string()),
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-team-a-api-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "namespace": "team-a",
        "labels": {"app": "worker"},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/worker"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_workload_selector_namespace_mismatch_does_not_apply() {
    // Selector requires namespace=team-a (with empty labels = any workload in
    // team-a). Proxy is in team-b → policy must NOT apply.
    let selector = WorkloadSelector {
        labels: HashMap::new(),
        namespace: Some("team-a".to_string()),
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "wl-team-a-allow",
            PolicyScope::WorkloadSelector { selector },
            PolicyAction::Allow,
        )],
        "namespace": "team-b",
        "labels": {},
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/anyone"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_cross_namespace_deny_and_in_namespace_allow_compose_correctly() {
    // The original bug surfaces here: a Namespace{team-a} DENY plus a
    // MeshWide ALLOW. Pre-fix: the team-a DENY would return Reject regardless
    // of which namespace the proxy lived in. Post-fix: in team-b only the
    // MeshWide ALLOW applies → Continue.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [
            policy_with_scope(
                "team-a-deny",
                PolicyScope::Namespace { namespace: "team-a".to_string() },
                PolicyAction::Deny,
            ),
            policy_with_scope(
                "mesh-wide-allow",
                PolicyScope::MeshWide,
                PolicyAction::Allow,
            ),
        ],
        "namespace": "team-b",
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));

    let result = plugin.authorize(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn mesh_authz_slice_embedded_identity_drives_scope_filter() {
    // mesh-mode injection passes a full `mesh_slice` whose `namespace` and
    // `labels` describe the proxy's own workload. The plugin must use those
    // when filtering policies — explicit namespace/labels override is not
    // required when the slice already carries the identity.
    use ferrum_edge::modes::mesh::slice::MeshSlice;

    let slice = MeshSlice {
        namespace: "team-b".to_string(),
        labels: [("app".to_string(), "worker".to_string())]
            .into_iter()
            .collect(),
        mesh_policies: vec![policy_with_scope(
            "team-a-deny",
            PolicyScope::Namespace {
                namespace: "team-a".to_string(),
            },
            PolicyAction::Deny,
        )],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({"mesh_slice": slice})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-b/sa/worker"));

    let result = plugin.authorize(&mut ctx).await;

    // Pre-fix: team-a-deny would deny team-b traffic. Post-fix: filtered out.
    assert!(matches!(result, PluginResult::Continue));
}

// ── requestPrincipals JWT enforcement (Phase C) ─────────────────────────────
//
// These tests pin the Istio-compatible `requestPrincipals` semantics:
//
// 1. `jwks_auth` sets `ctx.metadata["mesh.request_principal"]` = `{iss}/{sub}`.
// 2. `mesh_authz` passes that metadata value as `MeshAuthzRequest.request_principal`.
// 3. `MeshRule.request_principals` (from `from[].source.requestPrincipals`)
//    filters rules by glob-matching the request principal.
// 4. Empty `request_principals` means "any" (no filter).
// 5. Non-empty `request_principals` + no JWT (`None`) fails the match.

fn request_principal_policy(name: &str, action: PolicyAction, patterns: Vec<String>) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector::default(),
        },
        rules: vec![MeshRule {
            request_principals: patterns,
            action,
            ..MeshRule::default()
        }],
    }
}

#[tokio::test]
async fn mesh_authz_request_principals_allow_matching_jwt() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-jwt",
            PolicyAction::Allow,
            vec!["https://auth.example.com/user-123".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://auth.example.com/user-123".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "matching request principal should be allowed, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_non_matching_jwt() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-jwt",
            PolicyAction::Allow,
            vec!["https://auth.example.com/admin-*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://auth.example.com/user-123".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("non-matching request principal should be denied, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("implicit-deny")
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_missing_jwt() {
    // A rule requiring requestPrincipals must reject anonymous (no-JWT) requests.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-any-jwt",
            PolicyAction::Allow,
            vec!["*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    // No mesh.request_principal metadata — anonymous request

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("missing JWT should trigger implicit deny, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_request_principals_wildcard_matches_any_jwt() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "require-any-jwt",
            PolicyAction::Allow,
            vec!["*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://any-issuer.example.com/any-subject".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "wildcard should match any JWT principal, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_empty_request_principals_allows_anonymous() {
    // An empty request_principals list means "no filter" — anonymous is fine.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "no-jwt-constraint",
            PolicyAction::Allow,
            vec![],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "empty request_principals should allow anonymous, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_rule_blocks_jwt() {
    // A DENY rule with requestPrincipals should block matching JWTs.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "deny-admin",
            PolicyAction::Deny,
            vec!["https://auth.example.com/admin-*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://auth.example.com/admin-root".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("deny rule should block matching JWT, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("deny-admin")
    );
}

#[tokio::test]
async fn mesh_authz_request_principals_deny_rule_skips_non_matching_jwt() {
    // A DENY rule with requestPrincipals should NOT block non-matching JWTs.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [request_principal_policy(
            "deny-admin",
            PolicyAction::Deny,
            vec!["https://auth.example.com/admin-*".to_string()],
        )]
    }))
    .expect("plugin config");
    let mut ctx = request_context(None);
    ctx.metadata.insert(
        "mesh.request_principal".to_string(),
        "https://auth.example.com/user-123".to_string(),
    );

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "deny rule should not block non-matching JWT, got {result:?}"
    );
}

// GAP-2M.4 - per-pod policy scoping for node-waypoint topology.
//
// When `per_pod_policy_scoping: true`, MeshAuthz skips the construction-time
// slice-level scope filter (one listener serves many pods, so the slice's
// namespace/labels don't represent a single workload). Instead, the
// per-request filter consults the `PolicyScopeCache` set on `RequestContext`
// by the node-waypoint accept path. These tests cover:
//   1. Namespace-scoped policy applies only to pods in that namespace.
//   2. Workload-selector ALLOW gates implicit-deny by source-pod labels.
//   3. Missing scope + per_pod_policy_scoping=true fails closed (403) when
//      scoped policies exist, and falls through to mesh-wide-only when the
//      mesh has only mesh-wide policies, so scoped policies cannot leak.
//   4. Disabled path preserves the construction-time filter.

#[tokio::test]
async fn mesh_authz_per_pod_scoping_namespace_scope_filters_by_source_pod() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
    use std::sync::Arc;

    let team_a_deny = policy_with_scope(
        "team-a-deny",
        PolicyScope::Namespace {
            namespace: "team-a".to_string(),
        },
        PolicyAction::Deny,
    );
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [team_a_deny],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    // Source pod in team-b: team-a's namespace-scoped DENY must not apply.
    let mut ctx_team_b = request_context(Some("spiffe://cluster.local/ns/team-b/sa/client"));
    ctx_team_b.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/team-b/sa/client").expect("spiffe"),
        "team-b",
        HashMap::new(),
    )));
    let result_b = plugin.authorize(&mut ctx_team_b).await;
    assert!(
        matches!(result_b, PluginResult::Continue),
        "team-b traffic must not be denied by a team-a-scoped DENY, got {result_b:?}"
    );

    // Source pod in team-a: team-a's namespace-scoped DENY must apply.
    let mut ctx_team_a = request_context(Some("spiffe://cluster.local/ns/team-a/sa/client"));
    ctx_team_a.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/team-a/sa/client").expect("spiffe"),
        "team-a",
        HashMap::new(),
    )));
    let result_a = plugin.authorize(&mut ctx_team_a).await;
    match result_a {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("team-a traffic must be denied, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_workload_selector_filter_blocks_implicit_deny_leak() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
    use std::sync::Arc;

    // ALLOW scoped to (app=reviews) must not raise implicit-deny for
    // pods that don't match that selector.
    let selector_for_reviews = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
        namespace: None,
    };
    let allow_reviews = policy_with_scope(
        "reviews-allow",
        PolicyScope::WorkloadSelector {
            selector: selector_for_reviews,
        },
        PolicyAction::Allow,
    );
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [allow_reviews],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    // Source pod is `app=billing`. The reviews-allow policy is filtered out
    // by the per-pod scope, so the authz engine sees an empty policy set
    // and falls through to allow.
    let mut ctx_billing = request_context(Some("spiffe://cluster.local/ns/default/sa/billing"));
    ctx_billing.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/billing").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "billing".to_string())]),
    )));
    let result = plugin.authorize(&mut ctx_billing).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "workload-selector ALLOW for app=reviews must not implicit-deny app=billing, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_service_egress_uses_destination_policy_scope() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let dst_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/dst").expect("spiffe");
    let dst_selector = WorkloadSelector {
        labels: HashMap::from([("app".to_string(), "dst".to_string())]),
        namespace: None,
    };
    let dst_allow_trusted = MeshPolicy {
        name: "dst-allow-trusted".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: dst_selector,
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/trusted".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice {
        mesh_policies: vec![dst_allow_trusted],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: dst_spiffe.clone(),
            }],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![Workload {
            spiffe_id: dst_spiffe,
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
            // The outbound materializer admits explicit WorkloadRef matches
            // whose legacy service metadata does not name the Service, as long
            // as no exact metadata match exists. Authz must use the same
            // destination workload selection or destination-scoped policies can
            // disappear on this materialized route.
            service_name: "legacy-dst".to_string(),
            addresses: vec!["10.0.0.20".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/untrusted"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/untrusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-outbound-default-dst-80",
            "namespace": "default",
            "hosts": ["dst.default.svc.cluster.local"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "__mesh-out-upstream-default-dst-80"
        }))
        .expect("proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "destination-scoped ALLOW must remain applicable and implicit-deny untrusted source, got {other:?}"
        ),
    }

    let mut trusted_ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    trusted_ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    trusted_ctx.matched_proxy = ctx.matched_proxy.clone();

    let result = plugin.authorize(&mut trusted_ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed for the destination workload, got {result:?}"
    );
    assert_eq!(
        trusted_ctx
            .metadata
            .get("mesh_authz.node_waypoint_authorized_upstream_id")
            .map(String::as_str),
        Some("__mesh-out-upstream-default-dst-80")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_service_egress_requires_all_destination_scopes_to_allow() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    fn workload_allow_policy(name: &str, track: &str, source_principal: &str) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("track".to_string(), track.to_string())]),
                    namespace: None,
                },
            },
            rules: vec![MeshRule {
                from: vec![PrincipalMatch {
                    spiffe_id_pattern: Some(source_principal.to_string()),
                    namespace_pattern: None,
                    trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                    trust_domain_pattern: None,
                }],
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }
    }

    let stable_spiffe =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/stable").expect("spiffe");
    let canary_spiffe =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/canary").expect("spiffe");
    let slice = MeshSlice {
        mesh_policies: vec![
            workload_allow_policy(
                "stable-allow-trusted",
                "stable",
                "spiffe://cluster.local/ns/default/sa/trusted",
            ),
            workload_allow_policy(
                "canary-allow-canary-client",
                "canary",
                "spiffe://cluster.local/ns/default/sa/canary-client",
            ),
        ],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![
                WorkloadRef {
                    spiffe_id: stable_spiffe.clone(),
                },
                WorkloadRef {
                    spiffe_id: canary_spiffe.clone(),
                },
            ],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![
            Workload {
                spiffe_id: stable_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "dst".to_string()),
                        ("track".to_string(), "stable".to_string()),
                    ]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.0.20".to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
            Workload {
                spiffe_id: canary_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "dst".to_string()),
                        ("track".to_string(), "canary".to_string()),
                    ]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.0.21".to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
        ],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-outbound-default-dst-80",
            "namespace": "default",
            "hosts": ["dst.default.svc.cluster.local"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "__mesh-out-upstream-default-dst-80"
        }))
        .expect("proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "source allowed for only one possible Service backend must be denied, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn mesh_authz_node_waypoint_direct_service_backend_uses_destination_scope() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let dst_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/dst").expect("spiffe");
    let dst_allow_trusted = MeshPolicy {
        name: "dst-allow-trusted".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/trusted".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice {
        mesh_policies: vec![dst_allow_trusted],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: dst_spiffe.clone(),
            }],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![Workload {
            spiffe_id: dst_spiffe,
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
            service_name: "dst".to_string(),
            addresses: vec!["10.0.0.20".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let direct_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "vs-direct-dst",
            "namespace": "default",
            "hosts": ["dst.default.svc.cluster.local"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "dst.default.svc.cluster.local",
            "backend_port": 80
        }))
        .expect("proxy"),
    );

    let mut untrusted = request_context(Some("spiffe://cluster.local/ns/default/sa/untrusted"));
    untrusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/untrusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    untrusted.matched_proxy = Some(Arc::clone(&direct_proxy));
    match plugin.authorize(&mut untrusted).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("direct service backend must evaluate destination policy, got {other:?}"),
    }

    let mut trusted = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    trusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    trusted.matched_proxy = Some(direct_proxy);
    let result = plugin.authorize(&mut trusted).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed for direct service backend, got {result:?}"
    );
    assert_eq!(
        trusted
            .metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("dst.default.svc.cluster.local|80")
    );
    let aliases = trusted
        .metadata
        .get("mesh_authz.node_waypoint_authorized_backend_aliases")
        .expect("authorized backend aliases");
    assert!(
        aliases.split(',').any(|value| value == "dst|80"),
        "same-namespace short Service alias should be authorized for route overrides: {aliases}"
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_does_not_authorize_backend_when_upstream_is_set() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let dst_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/dst").expect("spiffe");
    let dst_allow_trusted = MeshPolicy {
        name: "dst-allow-trusted".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/trusted".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice {
        mesh_policies: vec![dst_allow_trusted],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: dst_spiffe.clone(),
            }],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![Workload {
            spiffe_id: dst_spiffe,
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
            service_name: "dst".to_string(),
            addresses: vec!["10.0.0.20".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "custom-upstream-proxy",
            "namespace": "default",
            "hosts": ["example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "dst.default.svc.cluster.local",
            "backend_port": 80,
            "upstream_id": "custom-upstream"
        }))
        .expect("proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "custom upstream should not be evaluated under the backend host's Service scope, got {result:?}"
    );
    assert!(
        !ctx.metadata
            .contains_key("mesh_authz.node_waypoint_authorized_backend"),
        "backend authorization metadata must not be stamped when upstream_id controls dispatch"
    );
    assert!(
        !ctx.metadata
            .contains_key("mesh_authz.node_waypoint_authorized_upstream_id"),
        "unknown custom upstream must not be stamped as destination-authorized"
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_short_service_backend_resolves_in_proxy_namespace() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let default_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/dst").expect("spiffe");
    let other_spiffe = SpiffeId::new("spiffe://cluster.local/ns/other/sa/dst").expect("spiffe");
    let dst_allow_trusted = MeshPolicy {
        name: "dst-allow-trusted".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "default-dst".to_string())]),
                namespace: None,
            },
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/trusted".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice {
        mesh_policies: vec![dst_allow_trusted],
        services: vec![
            MeshService {
                name: "dst".to_string(),
                namespace: "default".to_string(),
                ports: vec![ServicePort {
                    port: 80,
                    protocol: AppProtocol::Http,
                    name: None,
                    target_port: None,
                }],
                workloads: vec![WorkloadRef {
                    spiffe_id: default_spiffe.clone(),
                }],
                protocol_overrides: HashMap::new(),
                cluster_ips: Vec::new(),
            },
            MeshService {
                name: "dst".to_string(),
                namespace: "other".to_string(),
                ports: vec![ServicePort {
                    port: 80,
                    protocol: AppProtocol::Http,
                    name: None,
                    target_port: None,
                }],
                workloads: vec![WorkloadRef {
                    spiffe_id: other_spiffe.clone(),
                }],
                protocol_overrides: HashMap::new(),
                cluster_ips: Vec::new(),
            },
        ],
        workloads: vec![
            Workload {
                spiffe_id: default_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "default-dst".to_string())]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.0.20".to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
            Workload {
                spiffe_id: other_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "other-dst".to_string())]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.1.20".to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "other".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
        ],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let short_backend_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "vs-direct-short-dst",
            "namespace": "default",
            "hosts": ["example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "dst",
            "backend_port": 80
        }))
        .expect("proxy"),
    );

    let mut untrusted = request_context(Some("spiffe://cluster.local/ns/default/sa/untrusted"));
    untrusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/untrusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    untrusted.matched_proxy = Some(Arc::clone(&short_backend_proxy));
    match plugin.authorize(&mut untrusted).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("short service backend must resolve to default/dst scope, got {other:?}"),
    }

    let mut trusted = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    trusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    trusted.matched_proxy = Some(short_backend_proxy);
    let result = plugin.authorize(&mut trusted).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed through namespace-relative short backend, got {result:?}"
    );
    assert_eq!(
        trusted
            .metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("dst|80")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_direct_service_backend_uses_route_cluster_domain_alias() {
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "cluster_domain": "cluster.local",
        "cluster_domains": ["cluster.local", "corp.example"],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let direct_service_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "gwapi-direct-service-custom-domain",
            "namespace": "default",
            "hosts": ["api.example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "dst.default.svc.corp.example",
            "backend_port": 80
        }))
        .expect("proxy"),
    );

    let mut trusted = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    trusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    trusted.matched_proxy = Some(direct_service_proxy);
    let result = plugin.authorize(&mut trusted).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed through K8s route-domain service alias, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_unknown_virtual_service_upstream_fails_closed() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "scoped-allow",
            PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                    namespace: None,
                },
            },
            PolicyAction::Allow,
        )],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "vs-split",
            "namespace": "default",
            "hosts": ["api.example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "istio-vs-upstream-default-api-0"
        }))
        .expect("proxy"),
    ));

    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("unknown VS upstream with scoped policies must fail closed, got {other:?}"),
    }
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.destination_scope_missing")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_virtual_service_split_upstream_uses_route_targets() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let dst_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/dst").expect("spiffe");
    let dst_allow_trusted = MeshPolicy {
        name: "dst-allow-trusted".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/trusted".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    let slice = MeshSlice {
        mesh_policies: vec![dst_allow_trusted],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: dst_spiffe.clone(),
            }],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![Workload {
            spiffe_id: dst_spiffe,
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
            service_name: "dst".to_string(),
            addresses: vec!["10.0.0.20".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
        "node_waypoint_route_upstreams": [{
            "id": "istio-vs-upstream-default-api-0",
            "namespace": "default",
            "targets": [
                {"host": "dst", "port": 80}
            ]
        }]
    }))
    .expect("plugin config");
    let split_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "vs-split",
            "namespace": "default",
            "hosts": ["api.example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "istio-vs-upstream-default-api-0"
        }))
        .expect("proxy"),
    );

    let mut untrusted = request_context(Some("spiffe://cluster.local/ns/default/sa/untrusted"));
    untrusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/untrusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    untrusted.matched_proxy = Some(Arc::clone(&split_proxy));
    match plugin.authorize(&mut untrusted).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("VS split upstream must evaluate destination policy, got {other:?}"),
    }

    let mut trusted = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    trusted.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    trusted.matched_proxy = Some(split_proxy);
    let result = plugin.authorize(&mut trusted).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed through VS split upstream, got {result:?}"
    );
    assert_eq!(
        trusted
            .metadata
            .get("mesh_authz.node_waypoint_authorized_upstream_id")
            .map(String::as_str),
        Some("istio-vs-upstream-default-api-0")
    );
}

fn node_waypoint_endpoint_route_slice() -> MeshSlice {
    let dst_spiffe = SpiffeId::new("spiffe://cluster.local/ns/default/sa/dst").expect("spiffe");
    let dst_allow_trusted = MeshPolicy {
        name: "dst-allow-trusted".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::WorkloadSelector {
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
        },
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/trusted".to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    };
    MeshSlice {
        mesh_policies: vec![dst_allow_trusted],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: Some(ServiceTargetPort::Number(8080)),
            }],
            workloads: vec![WorkloadRef {
                spiffe_id: dst_spiffe.clone(),
            }],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![Workload {
            spiffe_id: dst_spiffe,
            selector: WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "dst".to_string())]),
                namespace: None,
            },
            service_name: "dst".to_string(),
            addresses: vec!["10.0.0.20".to_string()],
            ports: Vec::new(),
            trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
            namespace: "default".to_string(),
            network: None,
            cluster: None,
            weight: None,
            locality: None,
            service_account: None,
            pod_uid: None,
            node_waypoint: None,
            remote_provenance: false,
        }],
        ..MeshSlice::default()
    }
}

fn node_waypoint_route_proxy(upstream_id: &str) -> Arc<Proxy> {
    Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "vs-split",
            "namespace": "default",
            "hosts": ["api.example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": upstream_id
        }))
        .expect("proxy"),
    )
}

fn node_waypoint_scoped_context(source_sa: &str, upstream_id: &str) -> RequestContext {
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    let principal = format!("spiffe://cluster.local/ns/default/sa/{source_sa}");
    let mut ctx = request_context(Some(&principal));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new(&principal).expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(node_waypoint_route_proxy(upstream_id));
    ctx
}

#[tokio::test]
async fn mesh_authz_node_waypoint_route_upstream_uses_endpoint_service_metadata() {
    let upstream_id = "gwapi-route-upstream-default-api-0";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "node_waypoint_route_upstreams": [{
            "id": upstream_id,
            "namespace": "default",
            "targets": [{
                "host": "10.0.0.20",
                "port": 8080,
                "service_namespace": "default",
                "service_name": "dst",
                "service_port": 80
            }]
        }]
    }))
    .expect("plugin config");
    let mut ctx = node_waypoint_scoped_context("trusted", upstream_id);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed through endpoint-expanded route target, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.node_waypoint_authorized_upstream_id")
            .map(String::as_str),
        Some(upstream_id)
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_direct_endpoint_backend_uses_destination_scope() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let direct_endpoint_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "gwapi-direct-endpoint",
            "namespace": "default",
            "hosts": ["api.example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.0.20",
            "backend_port": 8080
        }))
        .expect("proxy"),
    );

    let mut untrusted = request_context(Some("spiffe://cluster.local/ns/default/sa/untrusted"));
    untrusted.node_waypoint_policy_scope = Some(Arc::new(
        ferrum_edge::modes::mesh::runtime::PolicyScopeCache::new(
            SpiffeId::new("spiffe://cluster.local/ns/default/sa/untrusted").expect("spiffe"),
            "default",
            HashMap::from([("app".to_string(), "src".to_string())]),
        ),
    ));
    untrusted.matched_proxy = Some(Arc::clone(&direct_endpoint_proxy));
    match plugin.authorize(&mut untrusted).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("direct endpoint backend must evaluate destination policy, got {other:?}"),
    }

    let mut trusted = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    trusted.node_waypoint_policy_scope = Some(Arc::new(
        ferrum_edge::modes::mesh::runtime::PolicyScopeCache::new(
            SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
            "default",
            HashMap::from([("app".to_string(), "src".to_string())]),
        ),
    ));
    trusted.matched_proxy = Some(direct_endpoint_proxy);
    let result = plugin.authorize(&mut trusted).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "trusted source should be allowed through direct endpoint backend, got {result:?}"
    );
    assert_eq!(
        trusted
            .metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("10.0.0.20|8080")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_hbone_relay_uses_destination_scope_without_source_pod_scope() {
    let source_waypoint = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-source";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "trusted_hbone_assertors": [source_waypoint],
    }))
    .expect("plugin config");
    let relay_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.0.20",
            "backend_port": 8080
        }))
        .expect("proxy"),
    );

    let mut ctx = request_context(Some(source_waypoint));
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/trusted".to_string(),
    );
    ctx.matched_proxy = Some(relay_proxy);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "authenticated NodeWaypoint relay should evaluate destination scope without a captured source pod scope, got {result:?}"
    );
    assert!(
        !ctx.metadata.contains_key("mesh_authz.scope_missing"),
        "destination-scoped HBONE relay must not be rejected as missing a source pod scope"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.node_waypoint_authorized_backend")
            .map(String::as_str),
        Some("10.0.0.20|8080")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_hbone_relay_without_trusted_baggage_fails_closed() {
    let source_waypoint = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-source";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "trusted_hbone_assertors": [source_waypoint],
    }))
    .expect("plugin config");
    let relay_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.0.20",
            "backend_port": 8080
        }))
        .expect("proxy"),
    );

    for (name, peer, baggage) in [
        ("missing baggage", source_waypoint, None),
        (
            "untrusted assertor",
            "spiffe://cluster.local/ns/ferrum/sa/untrusted-waypoint",
            Some("source.principal=spiffe://cluster.local/ns/default/sa/trusted"),
        ),
    ] {
        let mut ctx = request_context(Some(peer));
        ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        ctx.metadata
            .insert("request_protocol".to_string(), "hbone".to_string());
        if let Some(baggage) = baggage {
            ctx.headers
                .insert("baggage".to_string(), baggage.to_string());
        }
        ctx.matched_proxy = Some(Arc::clone(&relay_proxy));

        let result = plugin.authorize(&mut ctx).await;

        assert!(
            matches!(
                result,
                PluginResult::Reject {
                    status_code: 403,
                    ..
                }
            ),
            "{name} must fail closed instead of evaluating destination scope under the relay identity, got {result:?}"
        );
        assert_eq!(
            ctx.metadata
                .get("mesh_authz.deny_policy")
                .map(String::as_str),
            Some("scope_missing"),
            "{name} must keep the missing-source-scope fail-closed marker"
        );
    }
}

#[tokio::test]
async fn mesh_authz_node_waypoint_source_side_hbone_still_requires_source_scope() {
    let source_waypoint = "spiffe://cluster.local/ns/ferrum/sa/node-waypoint-source";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "trusted_hbone_assertors": [source_waypoint],
    }))
    .expect("plugin config");
    let direct_endpoint_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "gwapi-direct-endpoint",
            "namespace": "default",
            "hosts": ["api.example.com"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.0.20",
            "backend_port": 8080
        }))
        .expect("proxy"),
    );

    let mut ctx = request_context(Some(source_waypoint));
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/default/sa/trusted".to_string(),
    );
    ctx.matched_proxy = Some(direct_endpoint_proxy);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "source-side HBONE-shaped traffic without a current source scope must fail closed, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("scope_missing")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_destination_scope_without_hbone_still_requires_source_scope() {
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let relay_proxy = Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-inbound-hbone-relay",
            "namespace": "",
            "hosts": [],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "10.0.0.20",
            "backend_port": 8080
        }))
        .expect("proxy"),
    );

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    ctx.matched_proxy = Some(relay_proxy);

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "non-HBONE missing-source-scope traffic must remain fail-closed, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("scope_missing")
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_route_upstream_with_mixed_unscoped_target_fails_closed() {
    let upstream_id = "gwapi-route-upstream-default-api-0";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "node_waypoint_route_upstreams": [{
            "id": upstream_id,
            "namespace": "default",
            "targets": [
                {
                    "host": "dst",
                    "port": 80
                },
                {
                    "host": "external.example.com",
                    "port": 443
                }
            ]
        }]
    }))
    .expect("plugin config");
    let mut ctx = node_waypoint_scoped_context("trusted", upstream_id);

    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("mixed scoped/unscoped route upstream must fail closed, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_node_waypoint_route_upstream_with_unmodeled_service_endpoint_fails_closed() {
    let upstream_id = "gwapi-route-upstream-default-api-0";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "node_waypoint_route_upstreams": [{
            "id": upstream_id,
            "namespace": "default",
            "targets": [{
                "host": "10.0.0.99",
                "port": 8080,
                "service_namespace": "default",
                "service_name": "dst",
                "service_port": 80
            }]
        }]
    }))
    .expect("plugin config");
    let mut ctx = node_waypoint_scoped_context("trusted", upstream_id);

    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!("route target with unmodeled endpoint must fail closed, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_authz_node_waypoint_endpoint_route_without_service_metadata_fails_closed() {
    let upstream_id = "gwapi-route-upstream-default-api-0";
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": node_waypoint_endpoint_route_slice(),
        "per_pod_policy_scoping": true,
        "node_waypoint_route_upstreams": [{
            "id": upstream_id,
            "namespace": "default",
            "targets": [{
                "host": "10.0.0.20",
                "port": 8080
            }]
        }]
    }))
    .expect("plugin config");
    let mut ctx = node_waypoint_scoped_context("trusted", upstream_id);

    match plugin.authorize(&mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 403),
        other => panic!(
            "endpoint-expanded route target without service metadata must fail closed, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn mesh_authz_node_waypoint_destination_scopes_follow_target_port_eligibility() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    fn workload_allow_policy(name: &str, track: &str, source_principal: &str) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("track".to_string(), track.to_string())]),
                    namespace: None,
                },
            },
            rules: vec![MeshRule {
                from: vec![PrincipalMatch {
                    spiffe_id_pattern: Some(source_principal.to_string()),
                    namespace_pattern: None,
                    trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                    trust_domain_pattern: None,
                }],
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }
    }

    let stable_spiffe =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/stable").expect("spiffe");
    let canary_spiffe =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/canary").expect("spiffe");
    let slice = MeshSlice {
        mesh_policies: vec![
            workload_allow_policy(
                "stable-allow-trusted",
                "stable",
                "spiffe://cluster.local/ns/default/sa/trusted",
            ),
            workload_allow_policy(
                "canary-allow-canary-client",
                "canary",
                "spiffe://cluster.local/ns/default/sa/canary-client",
            ),
        ],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: Some(ServiceTargetPort::Name("http".to_string())),
            }],
            workloads: vec![
                WorkloadRef {
                    spiffe_id: stable_spiffe.clone(),
                },
                WorkloadRef {
                    spiffe_id: canary_spiffe.clone(),
                },
            ],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![
            Workload {
                spiffe_id: stable_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "dst".to_string()),
                        ("track".to_string(), "stable".to_string()),
                    ]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.0.20".to_string()],
                ports: vec![WorkloadPort {
                    port: 8080,
                    protocol: AppProtocol::Http,
                    name: Some("http".to_string()),
                }],
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
            Workload {
                spiffe_id: canary_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "dst".to_string()),
                        ("track".to_string(), "canary".to_string()),
                    ]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.0.21".to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
        ],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-outbound-default-dst-80",
            "namespace": "default",
            "hosts": ["dst.default.svc.cluster.local"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "__mesh-out-upstream-default-dst-80"
        }))
        .expect("proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "workload without resolvable targetPort must not participate in destination authz, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_node_waypoint_destination_scopes_skip_unroutable_workloads() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;

    fn workload_allow_policy(name: &str, track: &str, source_principal: &str) -> MeshPolicy {
        MeshPolicy {
            name: name.to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("track".to_string(), track.to_string())]),
                    namespace: None,
                },
            },
            rules: vec![MeshRule {
                from: vec![PrincipalMatch {
                    spiffe_id_pattern: Some(source_principal.to_string()),
                    namespace_pattern: None,
                    trust_domain: Some(TrustDomain::new("cluster.local").expect("trust domain")),
                    trust_domain_pattern: None,
                }],
                to: Vec::new(),
                when: Vec::new(),
                request_principals: Vec::new(),
                not_request_principals: Vec::new(),
                source_negation: Default::default(),
                never_matches: false,
                action: PolicyAction::Allow,
            }],
        }
    }

    let stable_spiffe =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/stable").expect("spiffe");
    let pending_spiffe =
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/pending").expect("spiffe");
    let slice = MeshSlice {
        mesh_policies: vec![
            workload_allow_policy(
                "stable-allow-trusted",
                "stable",
                "spiffe://cluster.local/ns/default/sa/trusted",
            ),
            workload_allow_policy(
                "pending-allow-pending-client",
                "pending",
                "spiffe://cluster.local/ns/default/sa/pending-client",
            ),
        ],
        services: vec![MeshService {
            name: "dst".to_string(),
            namespace: "default".to_string(),
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: None,
                target_port: None,
            }],
            workloads: vec![
                WorkloadRef {
                    spiffe_id: stable_spiffe.clone(),
                },
                WorkloadRef {
                    spiffe_id: pending_spiffe.clone(),
                },
            ],
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        workloads: vec![
            Workload {
                spiffe_id: stable_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "dst".to_string()),
                        ("track".to_string(), "stable".to_string()),
                    ]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: vec!["10.0.0.20".to_string()],
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
            Workload {
                spiffe_id: pending_spiffe,
                selector: WorkloadSelector {
                    labels: HashMap::from([
                        ("app".to_string(), "dst".to_string()),
                        ("track".to_string(), "pending".to_string()),
                    ]),
                    namespace: None,
                },
                service_name: "dst".to_string(),
                addresses: Vec::new(),
                ports: Vec::new(),
                trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
                namespace: "default".to_string(),
                network: None,
                cluster: None,
                weight: None,
                locality: None,
                service_account: None,
                pod_uid: None,
                node_waypoint: None,
                remote_provenance: false,
            },
        ],
        ..MeshSlice::default()
    };
    let plugin = MeshAuthz::new(&json!({
        "mesh_slice": slice,
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/trusted"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/trusted").expect("spiffe"),
        "default",
        HashMap::from([("app".to_string(), "src".to_string())]),
    )));
    ctx.matched_proxy = Some(Arc::new(
        serde_json::from_value::<Proxy>(json!({
            "id": "__mesh-outbound-default-dst-80",
            "namespace": "default",
            "hosts": ["dst.default.svc.cluster.local"],
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "",
            "backend_port": 0,
            "upstream_id": "__mesh-out-upstream-default-dst-80"
        }))
        .expect("proxy"),
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "workload with no addresses must not participate in destination authz, got {result:?}"
    );
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_missing_scope_fails_closed_when_scoped_policies_present() {
    // Per-pod scoping is enabled, a namespace-scoped policy exists, and this
    // request has no per-pod scope. After the single-generation resolver, a
    // missing scope means the workload's hash left the live slice gate (the pod
    // was removed or re-keyed) — the scope is derived from the same slice that
    // vouches the identity, so it is not an enrollment race. A long-lived
    // HTTP/2/HBONE connection from a removed workload must therefore fail closed
    // for scoped authz rather than silently dropping to mesh-wide-only, matching
    // the stream path.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [
            policy_with_scope(
                "team-a-deny",
                PolicyScope::Namespace { namespace: "team-a".to_string() },
                PolicyAction::Deny,
            ),
            policy_with_scope(
                "mesh-wide-allow",
                PolicyScope::MeshWide,
                PolicyAction::Allow,
            ),
        ],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    // Intentionally do not set node_waypoint_policy_scope.

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "missing per-pod scope with scoped policies present must fail closed, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.deny_policy")
            .map(String::as_str),
        Some("scope_missing"),
        "fail-closed reject must stamp deny_policy=scope_missing"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.scope_missing")
            .map(String::as_str),
        Some("true"),
    );
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_missing_scope_falls_through_when_only_mesh_wide() {
    // With ONLY mesh-wide policies the mesh is fully evaluable without a per-pod
    // scope, so a missing scope falls through to mesh-wide-only evaluation
    // (here: allow) rather than failing closed — matching the stream path.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    // Intentionally do not set node_waypoint_policy_scope.

    let result = plugin.authorize(&mut ctx).await;

    assert!(
        matches!(result, PluginResult::Continue),
        "missing scope with only mesh-wide policies should evaluate mesh-wide, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .get("mesh_authz.scope_missing")
            .map(String::as_str),
        Some("true"),
    );
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_missing_scope_sets_scope_missing_metadata() {
    // With only mesh-wide policies configured (as here) and the request
    // carrying no node_waypoint_policy_scope, the plugin evaluates mesh-wide
    // and must surface `mesh_authz.scope_missing` so operators can see the
    // fall-through in transaction logs. (With scoped policies present this same
    // missing-scope state fails closed instead — covered separately.)
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    // Intentionally do not set node_waypoint_policy_scope.

    let _ = plugin.authorize(&mut ctx).await;

    assert_eq!(
        ctx.metadata
            .get("mesh_authz.scope_missing")
            .map(String::as_str),
        Some("true"),
        "missing per-pod scope must surface mesh_authz.scope_missing metadata"
    );
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_present_scope_does_not_set_scope_missing_metadata() {
    use ferrum_edge::identity::SpiffeId;
    use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
    use std::sync::Arc;

    // With per_pod_policy_scoping on AND a populated scope cache, the
    // missing-scope flag must NOT be set — that flag is a race signal,
    // not a per-request always-on marker.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.node_waypoint_policy_scope = Some(Arc::new(PolicyScopeCache::new(
        SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("spiffe"),
        "default",
        HashMap::new(),
    )));

    let _ = plugin.authorize(&mut ctx).await;

    assert!(
        !ctx.metadata.contains_key("mesh_authz.scope_missing"),
        "populated per-pod scope must not set mesh_authz.scope_missing"
    );
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_disabled_does_not_set_scope_missing_metadata() {
    // When per_pod_policy_scoping is off (sidecar/ambient/east-west/egress
    // topologies), the missing-scope flag must never appear, even when the
    // request happens to have no node_waypoint_policy_scope.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));

    let _ = plugin.authorize(&mut ctx).await;

    assert!(
        !ctx.metadata.contains_key("mesh_authz.scope_missing"),
        "disabled per_pod_policy_scoping must not surface scope_missing metadata"
    );
}

#[tokio::test]
async fn mesh_authz_per_pod_scoping_disabled_path_preserves_construction_filter() {
    // With `per_pod_policy_scoping` defaulting to false (or absent), the
    // construction-time filter still applies and a namespace-scoped DENY
    // outside the proxy's namespace is dropped at construction. The
    // request hot path therefore never sees it, and `node_waypoint_policy_scope`
    // on the context is a no-op. This locks in the existing behaviour for
    // sidecar / ambient / east-west / egress-gateway topologies.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "team-a-deny",
            PolicyScope::Namespace { namespace: "team-a".to_string() },
            PolicyAction::Deny,
        )],
        // Proxy is in team-b — team-a DENY filtered at construction time.
        "namespace": "team-b",
    }))
    .expect("plugin config");

    let mut ctx = request_context(Some("spiffe://cluster.local/ns/team-a/sa/client"));
    // Even if a scope cache was set, it should be ignored because the
    // construction-time filter has already removed the team-a policy.
    let result = plugin.authorize(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "construction filter must drop team-a policy from a team-b proxy, got {result:?}"
    );
}

// GAP-2M.4 (stream path) - on_stream_connect per-pod policy scoping.
//
// The `authorize` HTTP path is covered by the tests above. The stream path
// (`on_stream_connect`) has an identical per-pod scoping branch and must
// satisfy the same three guarantees:
//   a. Missing `node_waypoint_policy_scope` fails closed (Reject 403) when
//      scoped policies exist; a mesh-wide-only mesh falls through to mesh-wide
//      evaluation.
//   b. A MeshWide DENY fires and closes the stream connection.
//   c. `mesh_authz.scope_missing` is stamped on the stream context when
//      per_pod_policy_scoping is enabled and the scope is absent.

#[tokio::test]
async fn mesh_authz_on_stream_connect_rejects_when_scope_missing() {
    // (a) Missing per-pod scope must fail closed to prevent bypassing scoped
    // policies on node-waypoint stream traffic.
    let ns_deny = policy_with_scope(
        "team-a-deny",
        PolicyScope::Namespace {
            namespace: "team-a".to_string(),
        },
        PolicyAction::Deny,
    );
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [ns_deny],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = stream_context();
    // Intentionally do not set node_waypoint_policy_scope — scope is None.
    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "missing scope with a scoped policy present must close the stream via Reject, got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .as_ref()
            .and_then(|m| m.get("mesh_authz.deny_policy"))
            .map(String::as_str),
        Some("scope_missing"),
        "fail-closed reject must stamp deny_policy=scope_missing"
    );
}

#[tokio::test]
async fn mesh_authz_on_stream_connect_mesh_wide_deny_closes_connection() {
    // (b) A MeshWide DENY always applies regardless of per-pod scoping —
    // it is not gated on a pod scope cache and must close the stream.
    let mesh_wide_deny =
        policy_with_scope("mesh-wide-deny", PolicyScope::MeshWide, PolicyAction::Deny);
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [mesh_wide_deny],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = stream_context();
    // No scope set — only mesh-wide policies survive, and this one is DENY.
    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(
        matches!(
            result,
            PluginResult::Reject {
                status_code: 403,
                ..
            }
        ),
        "MeshWide DENY must close the stream via Reject, got {result:?}"
    );
    let deny = ctx
        .metadata
        .as_ref()
        .and_then(|m| m.get("mesh_authz.deny_policy"))
        .map(String::as_str);
    assert_ne!(
        deny,
        Some("scope_missing"),
        "MeshWide DENY must be evaluated, not short-circuited"
    );
    assert_eq!(
        deny,
        Some("mesh-wide-deny"),
        "deny must come from the MeshWide policy"
    );
}

#[tokio::test]
async fn mesh_authz_on_stream_connect_scope_missing_metadata_stamped() {
    // (c) With only mesh-wide policies (as here), when per_pod_policy_scoping
    // is on and no scope cache is present, `mesh_authz.scope_missing` must
    // appear in the stream connection metadata so operators can observe the
    // mesh-wide fall-through in transaction logs.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [policy_with_scope(
            "mesh-wide-allow",
            PolicyScope::MeshWide,
            PolicyAction::Allow,
        )],
        "per_pod_policy_scoping": true,
    }))
    .expect("plugin config");

    let mut ctx = stream_context();
    // Intentionally do not set node_waypoint_policy_scope.
    let result = plugin.on_stream_connect(&mut ctx).await;
    assert!(
        matches!(result, PluginResult::Continue),
        "mesh-wide ALLOW with scope missing must NOT be rejected (no over-rejection), got {result:?}"
    );
    assert_eq!(
        ctx.metadata
            .as_ref()
            .and_then(|m| m.get("mesh_authz.scope_missing"))
            .map(String::as_str),
        Some("true"),
        "missing per-pod scope on stream must surface mesh_authz.scope_missing metadata"
    );
}

#[tokio::test]
async fn workload_metrics_inbound_listener_stamps_mesh_direction_inbound() {
    // GAP-3F: the mesh inbound listener stamps `ctx.mesh_direction = Inbound`
    // before the plugin chain runs, and `workload_metrics` then surfaces it
    // as `mesh.direction = "inbound"` in transaction metadata so the log
    // path can decide CLIENT vs SERVER span kind.
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("mesh.direction").map(String::as_str),
        Some("inbound")
    );
}

#[tokio::test]
async fn workload_metrics_outbound_listener_stamps_mesh_direction_outbound() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/default/sa/client"));
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("mesh.direction").map(String::as_str),
        Some("outbound")
    );
}

fn workload_metrics_tracing_plugin() -> WorkloadMetrics {
    WorkloadMetrics::new(&json!({
        "sampling_percentage": 100.0
    }))
    .expect("tracing workload metrics config")
}

fn trace_header_remover(header: &str) -> RequestTransformer {
    RequestTransformer::new(&json!({
        "rules": [{
            "operation": "remove",
            "target": "header",
            "key": header
        }]
    }))
    .expect("trace header removal config")
}

fn trace_header_replacer(header: &str, value: &str) -> RequestTransformer {
    RequestTransformer::new(&json!({
        "rules": [{
            "operation": "update",
            "target": "header",
            "key": header,
            "value": value
        }]
    }))
    .expect("trace header replacement config")
}

fn trace_header_adder(header: &str, value: &str) -> RequestTransformer {
    RequestTransformer::new(&json!({
        "rules": [{
            "operation": "add",
            "target": "header",
            "key": header,
            "value": value
        }]
    }))
    .expect("trace header addition config")
}

fn inbound_trace_headers() -> HashMap<String, String> {
    HashMap::from([
        (
            "traceparent".to_string(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
        ),
        ("tracestate".to_string(), "vendor=value".to_string()),
    ])
}

fn assert_no_http_trace_metadata(ctx: &RequestContext) {
    for key in [
        "trace_id",
        "span_id",
        "parent_span_id",
        "trace_sampled",
        "traceparent",
        "tracestate",
    ] {
        assert!(
            !ctx.metadata.contains_key(key),
            "accepted transformed request retained stale {key}: {:?}",
            ctx.metadata
        );
    }
}

#[tokio::test]
async fn workload_metrics_propagates_valid_traceparent_replacement_as_authoritative() {
    let metrics = workload_metrics_tracing_plugin();
    let original_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let replacement_trace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let replacement_parent_span_id = "bbbbbbbbbbbbbbbb";
    let replacement_traceparent =
        format!("00-{replacement_trace_id}-{replacement_parent_span_id}-00");
    let transformer = trace_header_replacer("TraceParent", &replacement_traceparent);
    let mut ctx = request_context(None);
    ctx.headers = inbound_trace_headers();

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("trace_id").map(String::as_str),
        Some(original_trace_id)
    );
    assert_eq!(
        ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("true")
    );

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let transformed_traceparent = headers
        .remove("traceparent")
        .expect("transformer replaced traceparent");
    headers.insert("TraceParent".to_string(), transformed_traceparent);
    headers
        .remove("tracestate")
        .expect("inbound tracestate retained");
    headers.insert("TraceState".to_string(), "replacement=value".to_string());

    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let propagated = headers
        .get("traceparent")
        .expect("replacement traceparent propagated");
    assert!(propagated.starts_with(&format!("00-{replacement_trace_id}-")));
    assert!(propagated.ends_with("-00"));
    assert!(!propagated.contains(original_trace_id));
    assert_eq!(
        headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("traceparent"))
            .count(),
        1
    );
    assert_eq!(
        headers.get("tracestate").map(String::as_str),
        Some("replacement=value")
    );
    assert!(!headers.contains_key("TraceState"));
    assert_eq!(
        ctx.metadata.get("trace_id").map(String::as_str),
        Some(replacement_trace_id)
    );
    assert_eq!(
        ctx.metadata.get("parent_span_id").map(String::as_str),
        Some(replacement_parent_span_id)
    );
    assert_ne!(
        ctx.metadata.get("span_id").map(String::as_str),
        Some(replacement_parent_span_id)
    );
    assert_eq!(
        ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("false")
    );
    assert_eq!(
        ctx.metadata.get("traceparent").map(String::as_str),
        Some(propagated.as_str())
    );
}

#[tokio::test]
async fn workload_metrics_propagates_valid_traceparent_added_by_transformer() {
    let metrics = workload_metrics_tracing_plugin();
    let replacement_trace_id = "cccccccccccccccccccccccccccccccc";
    let replacement_parent_span_id = "dddddddddddddddd";
    let replacement_traceparent =
        format!("00-{replacement_trace_id}-{replacement_parent_span_id}-00");
    let transformer = trace_header_adder("TraceParent", &replacement_traceparent);
    let mut ctx = request_context(None);

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let local_trace_id = ctx
        .metadata
        .get("trace_id")
        .cloned()
        .expect("locally sampled trace ID");
    assert_ne!(local_trace_id, replacement_trace_id);

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let propagated = headers
        .get("traceparent")
        .expect("transformer-added traceparent propagated");
    assert!(propagated.starts_with(&format!("00-{replacement_trace_id}-")));
    assert!(propagated.ends_with("-00"));
    assert!(!propagated.contains(&local_trace_id));
    assert_eq!(
        ctx.metadata.get("trace_id").map(String::as_str),
        Some(replacement_trace_id)
    );
    assert_eq!(
        ctx.metadata.get("parent_span_id").map(String::as_str),
        Some(replacement_parent_span_id)
    );
    assert_eq!(
        ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("false")
    );
}

#[tokio::test]
async fn workload_metrics_does_not_restore_b3_context_removed_by_transformer() {
    let metrics = workload_metrics_tracing_plugin();
    let transformer = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-B3-TraceId"},
            {"operation": "remove", "target": "header", "key": "X-B3-SpanId"},
            {"operation": "remove", "target": "header", "key": "X-B3-Sampled"}
        ]
    }))
    .expect("B3 removal config");
    let original_trace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut ctx = request_context(None);
    ctx.headers = HashMap::from([
        ("x-b3-traceid".to_string(), original_trace_id.to_string()),
        ("x-b3-spanid".to_string(), "bbbbbbbbbbbbbbbb".to_string()),
        ("x-b3-sampled".to_string(), "1".to_string()),
    ]);

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("trace_id").map(String::as_str),
        Some(original_trace_id)
    );
    assert!(ctx.metadata.contains_key("traceparent"));

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("traceparent")
                && !name.eq_ignore_ascii_case("b3")
                && !name.to_ascii_lowercase().starts_with("x-b3-"))
    );
    assert!(!ctx.metadata.contains_key("traceparent"));
    assert_no_http_trace_metadata(&ctx);

    let mut response_headers = HashMap::new();
    let result = metrics
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!response_headers.contains_key("traceparent"));
}

#[tokio::test]
async fn workload_metrics_propagates_final_valid_b3_replacement() {
    let metrics = workload_metrics_tracing_plugin();
    let replacement_trace_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let replacement_parent_span_id = "ffffffffffffffff";
    let transformer = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "update",
                "target": "header",
                "key": "X-B3-TraceId",
                "value": replacement_trace_id
            },
            {
                "operation": "update",
                "target": "header",
                "key": "X-B3-SpanId",
                "value": replacement_parent_span_id
            },
            {
                "operation": "update",
                "target": "header",
                "key": "X-B3-Sampled",
                "value": "0"
            }
        ]
    }))
    .expect("B3 replacement config");
    let original_trace_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut ctx = request_context(None);
    ctx.headers = HashMap::from([
        ("x-b3-traceid".to_string(), original_trace_id.to_string()),
        ("x-b3-spanid".to_string(), "bbbbbbbbbbbbbbbb".to_string()),
        ("x-b3-sampled".to_string(), "1".to_string()),
    ]);

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    for (lower, mixed) in [
        ("x-b3-traceid", "X-B3-TraceId"),
        ("x-b3-spanid", "X-B3-SpanId"),
        ("x-b3-sampled", "X-B3-Sampled"),
    ] {
        let value = headers.remove(lower).expect("transformed B3 header");
        headers.insert(mixed.to_string(), value);
    }
    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let propagated = headers
        .get("traceparent")
        .expect("replacement B3 context propagated as W3C");
    assert!(propagated.starts_with(&format!("00-{replacement_trace_id}-")));
    assert!(propagated.ends_with("-00"));
    assert!(!propagated.contains(original_trace_id));
    assert_eq!(
        ctx.metadata.get("parent_span_id").map(String::as_str),
        Some(replacement_parent_span_id)
    );
    assert_eq!(
        ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("false")
    );
}

#[tokio::test]
async fn workload_metrics_sampling_only_b3_uses_final_transformed_headers() {
    let metrics = workload_metrics_tracing_plugin();

    let mut removed_ctx = request_context(None);
    removed_ctx
        .headers
        .insert("b3".to_string(), "1".to_string());
    let result = metrics.on_request_received(&mut removed_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        removed_ctx
            .metadata
            .get("trace_sampled")
            .map(String::as_str),
        Some("true")
    );
    let remover = trace_header_remover("b3");
    let mut removed_headers = removed_ctx.headers.clone();
    let result = remover
        .before_proxy(&mut removed_ctx, &mut removed_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics
        .before_proxy(&mut removed_ctx, &mut removed_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_no_http_trace_metadata(&removed_ctx);
    assert!(!removed_headers.contains_key("traceparent"));

    let mut flipped_ctx = request_context(None);
    flipped_ctx
        .headers
        .insert("x-b3-sampled".to_string(), "1".to_string());
    let result = metrics.on_request_received(&mut flipped_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let flipper = trace_header_replacer("x-b3-sampled", "0");
    let mut flipped_headers = flipped_ctx.headers.clone();
    let result = flipper
        .before_proxy(&mut flipped_ctx, &mut flipped_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics
        .before_proxy(&mut flipped_ctx, &mut flipped_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        flipped_ctx
            .metadata
            .get("trace_sampled")
            .map(String::as_str),
        Some("false")
    );
    assert!(!flipped_ctx.metadata.contains_key("trace_id"));
    assert!(!flipped_headers.contains_key("traceparent"));

    let mut added_ctx = request_context(None);
    let result = metrics.on_request_received(&mut added_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        added_ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("true")
    );
    let adder = trace_header_adder("x-b3-sampled", "0");
    let mut added_headers = added_ctx.headers.clone();
    let result = adder.before_proxy(&mut added_ctx, &mut added_headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics
        .before_proxy(&mut added_ctx, &mut added_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        added_ctx.metadata.get("trace_sampled").map(String::as_str),
        Some("false")
    );
    assert!(!added_ctx.metadata.contains_key("trace_id"));
    assert!(!added_headers.contains_key("traceparent"));
}

#[tokio::test]
async fn workload_metrics_rebuilds_custom_header_tags_from_final_headers() {
    let metrics = WorkloadMetrics::new(&json!({
        "custom_tags": {"fallback": "literal"},
        "custom_header_tags": {
            "tenant": "x-tenant",
            "fallback": "x-fallback"
        }
    }))
    .expect("custom header tag config");
    let remover = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "X-Tenant"},
            {"operation": "remove", "target": "header", "key": "X-Fallback"}
        ]
    }))
    .expect("custom header removal config");
    let mut ctx = request_context(None);
    ctx.headers = HashMap::from([
        ("x-tenant".to_string(), "early-tenant".to_string()),
        ("x-fallback".to_string(), "early-header".to_string()),
    ]);

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata.get("tenant").map(String::as_str),
        Some("early-tenant")
    );
    assert_eq!(
        ctx.metadata.get("fallback").map(String::as_str),
        Some("early-header")
    );
    let mut headers = ctx.headers.clone();
    let result = remover.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!ctx.metadata.contains_key("tenant"));
    assert_eq!(
        ctx.metadata.get("fallback").map(String::as_str),
        Some("literal"),
        "a removed header falls back to the configured literal tag"
    );

    let oversized = "x".repeat(1025);
    let oversized_transformer = trace_header_replacer("X-Tenant", &oversized);
    let mut oversized_ctx = request_context(None);
    oversized_ctx
        .headers
        .insert("x-tenant".to_string(), "early-tenant".to_string());
    let result = metrics.on_request_received(&mut oversized_ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let mut oversized_headers = oversized_ctx.headers.clone();
    let result = oversized_transformer
        .before_proxy(&mut oversized_ctx, &mut oversized_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics
        .before_proxy(&mut oversized_ctx, &mut oversized_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!oversized_ctx.metadata.contains_key("tenant"));
}

#[tokio::test]
async fn workload_metrics_does_not_restore_traceparent_removed_by_transformer() {
    let metrics = workload_metrics_tracing_plugin();
    let transformer = trace_header_remover("traceparent");
    let mut ctx = request_context(None);
    ctx.headers = inbound_trace_headers();
    assert!(
        transformer.priority() < metrics.priority(),
        "request_transformer must finalize request headers before workload_metrics"
    );

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("trace_id"));
    assert!(ctx.metadata.contains_key("traceparent"));

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("traceparent"));
    let tracestate = headers
        .remove("tracestate")
        .expect("transformer leaves inbound tracestate");
    headers.insert("TraceState".to_string(), tracestate);

    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("traceparent")
                && !name.eq_ignore_ascii_case("tracestate"))
    );
    assert!(!ctx.metadata.contains_key("traceparent"));
    assert!(!ctx.metadata.contains_key("tracestate"));
    assert_no_http_trace_metadata(&ctx);

    let mut response_headers = HashMap::new();
    let result = metrics
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!response_headers.contains_key("traceparent"));
}

#[tokio::test]
async fn workload_metrics_drops_added_tracestate_with_malformed_final_parent() {
    let metrics = workload_metrics_tracing_plugin();
    let transformer = RequestTransformer::new(&json!({
        "rules": [
            {
                "operation": "update",
                "target": "header",
                "key": "TraceParent",
                "value": "malformed"
            },
            {
                "operation": "add",
                "target": "header",
                "key": "TraceState",
                "value": "added=value"
            }
        ]
    }))
    .expect("malformed W3C replacement config");
    let mut ctx = request_context(None);
    ctx.headers.insert(
        "TraceParent".to_string(),
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_string(),
    );

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(ctx.metadata.contains_key("trace_id"));

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let malformed = headers
        .remove("traceparent")
        .expect("transformer replaced traceparent");
    headers.insert("TraceParent".to_string(), malformed);
    let added_tracestate = headers
        .remove("tracestate")
        .expect("transformer added tracestate");
    headers.insert("TraceState".to_string(), added_tracestate);

    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("traceparent")
                && !name.eq_ignore_ascii_case("tracestate"))
    );
    assert!(!ctx.metadata.contains_key("traceparent"));
    assert!(!ctx.metadata.contains_key("tracestate"));
    assert_no_http_trace_metadata(&ctx);
}

#[tokio::test]
async fn workload_metrics_final_b3_context_does_not_retain_captured_tracestate() {
    let metrics = workload_metrics_tracing_plugin();
    let b3_trace_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let b3_parent_span_id = "ffffffffffffffff";
    let transformer = RequestTransformer::new(&json!({
        "rules": [
            {"operation": "remove", "target": "header", "key": "TraceParent"},
            {
                "operation": "add",
                "target": "header",
                "key": "X-B3-TraceId",
                "value": b3_trace_id
            },
            {
                "operation": "add",
                "target": "header",
                "key": "X-B3-SpanId",
                "value": b3_parent_span_id
            },
            {
                "operation": "add",
                "target": "header",
                "key": "X-B3-Sampled",
                "value": "1"
            }
        ]
    }))
    .expect("final B3 context config");
    let mut ctx = request_context(None);
    ctx.headers = inbound_trace_headers();

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("tracestate"))
    );
    assert!(!ctx.metadata.contains_key("tracestate"));
    assert!(
        headers
            .get("traceparent")
            .expect("final B3 context propagates as W3C")
            .starts_with(&format!("00-{b3_trace_id}-"))
    );
    assert_eq!(
        ctx.metadata.get("trace_id").map(String::as_str),
        Some(b3_trace_id)
    );
}

#[tokio::test]
async fn workload_metrics_does_not_restore_tracestate_removed_by_transformer() {
    let metrics = workload_metrics_tracing_plugin();
    let transformer = trace_header_remover("tracestate");
    let mut ctx = request_context(None);
    ctx.headers = inbound_trace_headers();
    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("tracestate"));

    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(headers.contains_key("traceparent"));
    assert!(!headers.contains_key("tracestate"));
    assert!(!ctx.metadata.contains_key("tracestate"));
}

#[tokio::test]
async fn workload_metrics_keeps_unchanged_valid_trace_headers() {
    let metrics = workload_metrics_tracing_plugin();
    let transformer = trace_header_remover("x-private");
    let mut ctx = request_context(None);
    ctx.headers = inbound_trace_headers();
    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let propagated = headers
        .get("traceparent")
        .expect("valid traceparent propagated");
    assert!(propagated.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
    assert!(propagated.ends_with("-01"));
    assert_ne!(
        propagated,
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    );
    assert_eq!(
        headers.get("tracestate").map(String::as_str),
        Some("vendor=value")
    );
}

#[tokio::test]
async fn workload_metrics_keeps_early_trace_context_for_reject_observability() {
    let metrics = workload_metrics_tracing_plugin();
    let mut ctx = request_context(None);
    ctx.headers = inbound_trace_headers();
    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    // Authorization rejects before `before_proxy`, so the early context must
    // remain available to the rejection response and transaction summary.
    let mut response_headers = HashMap::new();
    let result = metrics
        .after_proxy(&mut ctx, 403, &mut response_headers)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(response_headers.contains_key("traceparent"));
    assert!(ctx.metadata.contains_key("trace_id"));
    assert!(ctx.metadata.contains_key("span_id"));
}

#[tokio::test]
async fn workload_metrics_rebuilds_source_identity_after_baggage_transform() {
    let metrics = WorkloadMetrics::new(&json!({
        "namespace": "payments",
        "workload_spiffe_id": "spiffe://cluster.local/ns/payments/sa/checkout",
        "labels": {"app": "checkout"},
        "trusted_hbone_assertors": ["spiffe://cluster.local/assertor"]
    }))
    .expect("workload metrics config");
    let transformer = trace_header_remover("baggage");
    let mut ctx = request_context(Some("spiffe://cluster.local/assertor"));
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    ctx.headers.insert(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/storefront/sa/frontend".to_string(),
    );

    let result = metrics.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.namespace")
            .map(String::as_str),
        Some("storefront")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.service_account")
            .map(String::as_str),
        Some("frontend")
    );

    let mut headers = ctx.headers.clone();
    let result = transformer.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    let result = metrics.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/assertor")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.trust_domain")
            .map(String::as_str),
        Some("cluster.local")
    );
    assert!(!ctx.metadata.contains_key("mesh.source.namespace"));
    assert!(!ctx.metadata.contains_key("mesh.source.service_account"));
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("unknown")
    );
}

#[tokio::test]
async fn workload_metrics_node_waypoint_http_outbound_uses_asserted_pod_before_baggage() {
    let plugin = WorkloadMetrics::new(&json!({
        "topology": "node_waypoint",
        "namespace": "istio-system",
        "workload_spiffe_id": "spiffe://cluster.local/ns/istio-system/sa/waypoint",
        "labels": {
            "service.istio.io/canonical-name": "node-waypoint"
        },
        "trusted_hbone_assertors": [
            "spiffe://cluster.local/ns/storefront/sa/frontend"
        ]
    }))
    .expect("plugin config");
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "reviews-proxy",
        "name": "reviews",
        "namespace": "default",
        "hosts": ["reviews.default.svc.cluster.local"],
        "backend_host": "127.0.0.1",
        "backend_port": 8080
    }))
    .expect("proxy fixture");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/storefront/sa/frontend"));
    ctx.node_waypoint_pod_uid = Some([7; 16]);
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    ctx.matched_proxy = Some(Arc::new(proxy));
    ctx.metadata
        .insert("request_protocol".to_string(), "hbone".to_string());
    let mut headers = HashMap::from([(
        "baggage".to_string(),
        "source.principal=spiffe://cluster.local/ns/attacker/sa/spoofed".to_string(),
    )]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/storefront/sa/frontend")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.source.namespace")
            .map(String::as_str),
        Some("storefront")
    );
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("frontend")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.destination.workload")
            .map(String::as_str),
        Some("reviews")
    );
}

#[tokio::test]
async fn workload_metrics_non_waypoint_outbound_keeps_local_source_semantics() {
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/local-client",
        "labels": {"app": "local-client"}
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/remote/sa/transport-peer"));
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/local-client")
    );
    assert_eq!(
        ctx.metadata.get("mesh.source.workload").map(String::as_str),
        Some("local-client")
    );
}

#[tokio::test]
async fn workload_metrics_node_waypoint_inbound_keeps_peer_as_source() {
    let plugin = WorkloadMetrics::new(&json!({
        "namespace": "default",
        "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/reviews",
        "labels": {"app": "reviews"}
    }))
    .expect("plugin config");
    let mut ctx = request_context(Some("spiffe://cluster.local/ns/storefront/sa/frontend"));
    ctx.node_waypoint_pod_uid = Some([8; 16]);
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
    let mut headers = HashMap::new();

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("mesh.source.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/storefront/sa/frontend")
    );
    assert_eq!(
        ctx.metadata
            .get("mesh.destination.principal")
            .map(String::as_str),
        Some("spiffe://cluster.local/ns/default/sa/reviews")
    );
}

#[tokio::test]
async fn workload_metrics_unstamped_request_does_not_emit_direction_metadata() {
    // Non-mesh listeners (file / db / cp / dp) leave `mesh_direction = None`.
    // The plugin must not invent a value, since downstream consumers rely on
    // "absent" as the signal that no mesh listener stamped this request.
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = request_context(None);
    let mut headers = HashMap::new();

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert!(!ctx.metadata.contains_key("mesh.direction"));
}

#[tokio::test]
async fn workload_metrics_stream_inbound_listener_stamps_mesh_direction() {
    let plugin = WorkloadMetrics::new(&json!({})).expect("plugin config");
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "tcp-proxy".to_string(),
        None,
        15432,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );
    ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);

    let result = plugin.on_stream_connect(&mut ctx).await;

    assert!(matches!(result, PluginResult::Continue));
    let metadata = ctx.metadata.expect("stream metadata");
    assert_eq!(
        metadata.get("mesh.direction").map(String::as_str),
        Some("inbound")
    );
}

#[tokio::test]
async fn workload_metrics_direction_emit_back_compat_default_is_server_only() {
    // When `direction_emit` is absent, the plugin must default to the
    // pre-GAP-3F server_only behaviour so existing deployments keep emitting
    // exactly the spans they did before.
    let plugin = WorkloadMetrics::new(&json!({})).expect("default plugin config");
    let mut ctx = request_context(None);
    ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    // The metadata stamp still records the listener-provided direction so the
    // outbound direction is observable in logs even on a server_only plugin.
    assert_eq!(
        ctx.metadata.get("mesh.direction").map(String::as_str),
        Some("outbound")
    );
}

#[tokio::test]
async fn workload_metrics_direction_emit_rejects_garbage_value() {
    // direction_emit accepts only known booleans; a wrong shape must be a
    // hard config error rather than silently defaulting to server_only.
    let result = WorkloadMetrics::new(&json!({
        "direction_emit": "client"
    }));
    let err = match result {
        Ok(_) => panic!("string direction_emit must be rejected"),
        Err(e) => e,
    };
    assert!(
        err.contains("direction_emit"),
        "config error must mention the field: {err}"
    );
}

// ── PROXY protocol stream IP split (source.ip vs remote.ip) ──────────────────

/// When inbound PROXY protocol is enabled the stream path produces two
/// distinct IP values: `direct_client_ip` (socket peer, the load balancer)
/// and `client_ip` (forwarded origin from the PROXY header).
///
/// `build_stream_condition_attributes` must map them to different `when:`
/// keys so policies can distinguish between them — mirroring the HTTP-path
/// split where `source.ip` = socket peer and `remote.ip` = XFF-resolved.
///
/// This test exercises the full `on_stream_connect` codepath with a
/// policy that gates on `source.ip` (should see the direct socket peer)
/// and a second policy that gates on `remote.ip` (should see the
/// forwarded/resolved address).
#[tokio::test]
async fn mesh_authz_stream_source_ip_uses_direct_socket_peer_not_forwarded() {
    // Policy: DENY if source.ip (socket peer) == "10.0.0.1"
    // This should trigger when direct_client_ip = "10.0.0.1", regardless of
    // the forwarded client_ip.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "deny-lb-peer",
            "namespace": "default",
            "scope": {"kind": "mesh_wide"},
            "rules": [{
                "when": [{"key": "source.ip", "values": ["10.0.0.1/32"]}],
                "action": "deny"
            }]
        }]
    }))
    .expect("plugin config");

    // direct_client_ip = LB socket peer; client_ip = forwarded origin from PROXY header.
    let mut ctx_peer_matches = stream_context();
    ctx_peer_matches.direct_client_ip = "10.0.0.1".to_string(); // socket peer = LB
    ctx_peer_matches.client_ip = "192.168.100.5".to_string(); // forwarded = real client

    // The DENY should fire because source.ip (direct socket peer) matches.
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx_peer_matches).await,
            PluginResult::Reject { .. }
        ),
        "source.ip when-condition must match the direct socket peer (direct_client_ip)"
    );

    // When the socket peer is different (10.0.0.2) and the forwarded origin
    // happens to be 10.0.0.1, source.ip should NOT match — source.ip is the
    // socket peer, not the forwarded address.
    let mut ctx_forwarded_matches = stream_context();
    ctx_forwarded_matches.direct_client_ip = "10.0.0.2".to_string(); // different peer
    ctx_forwarded_matches.client_ip = "10.0.0.1".to_string(); // forwarded = PROXY header value

    // The DENY must NOT fire because source.ip sees the socket peer (10.0.0.2),
    // not the forwarded address.
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx_forwarded_matches).await,
            PluginResult::Continue
        ),
        "source.ip when-condition must NOT match the forwarded client_ip"
    );
}

#[tokio::test]
async fn mesh_authz_stream_remote_ip_uses_forwarded_address_not_socket_peer() {
    // Policy: DENY if remote.ip (forwarded/resolved) == "192.168.100.5"
    // This should trigger when client_ip = "192.168.100.5", regardless of
    // the socket peer in direct_client_ip.
    let plugin = MeshAuthz::new(&json!({
        "mesh_policies": [{
            "name": "deny-forwarded-origin",
            "namespace": "default",
            "scope": {"kind": "mesh_wide"},
            "rules": [{
                "when": [{"key": "remote.ip", "values": ["192.168.100.5/32"]}],
                "action": "deny"
            }]
        }]
    }))
    .expect("plugin config");

    // client_ip = resolved forwarded address (PROXY header); direct = LB peer.
    let mut ctx_forwarded_matches = stream_context();
    ctx_forwarded_matches.direct_client_ip = "10.0.0.1".to_string(); // socket peer = LB
    ctx_forwarded_matches.client_ip = "192.168.100.5".to_string(); // forwarded origin

    // The DENY fires because remote.ip (forwarded address) matches.
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx_forwarded_matches).await,
            PluginResult::Reject { .. }
        ),
        "remote.ip when-condition must match the forwarded/resolved client_ip"
    );

    // When the socket peer is 192.168.100.5 but the forwarded address is
    // different, remote.ip should NOT match.
    let mut ctx_peer_matches = stream_context();
    ctx_peer_matches.direct_client_ip = "192.168.100.5".to_string(); // socket peer matches
    ctx_peer_matches.client_ip = "172.16.0.99".to_string(); // forwarded = different

    // The DENY must NOT fire because remote.ip sees the forwarded address
    // (172.16.0.99), not the socket peer.
    assert!(
        matches!(
            plugin.on_stream_connect(&mut ctx_peer_matches).await,
            PluginResult::Continue
        ),
        "remote.ip when-condition must NOT match the direct socket peer (direct_client_ip)"
    );
}
