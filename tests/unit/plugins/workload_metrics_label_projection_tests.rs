//! Typed mesh label projection (issue #6793).
//!
//! `workload_metrics` writes every `mesh.source.*` / `mesh.destination.*`
//! label through one writer that updates both the string projection in
//! `ctx.metadata` and the request's typed `MeshLabelShadow`. These tests pin:
//!
//! - the shadow equals the label subset of the eager metadata projection, for
//!   every direction / identity / configuration shape;
//! - a deferred request leaves exactly the label keys out of metadata and
//!   nothing else, with the same shadow;
//! - the typed metric key equals the string parser's key for the eager
//!   projection, in both modes, and falls back to the parser whenever another
//!   plugin rewrote, removed or added a label;
//! - the gateway mesh-dispatch overlay reaches the shadow;
//! - only a plugin view whose every plugin proves it cannot observe the
//!   labels defers the projection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ferrum_edge::PluginCache;
use ferrum_edge::PluginCapabilities;
use ferrum_edge::config::types::{GatewayConfig, PluginScope, Proxy};
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::plugins::mesh::prometheus_helpers::{
    mesh_request_key, mesh_request_key_for_request,
};
use ferrum_edge::plugins::mesh::service_graph::global_service_graph;
use ferrum_edge::plugins::mesh::telemetry_facts::MeshLabel;
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::{
    MetadataMap, Plugin, ProxyProtocol, RequestContext, TransactionSummary, create_plugin,
    log_with_mirror,
};
use serde_json::{Value, json};

use super::plugin_utils::{make_plugin_config_with_json, make_proxy};

const LOCAL_ID: &str = "spiffe://cluster.local/ns/payments/sa/checkout";
const PEER_ID: &str = "spiffe://cluster.local/ns/storefront/sa/frontend";
const SHORT_PEER_ID: &str = "spiffe://cluster.local/ztunnel";

fn spiffe(id: &str) -> SpiffeId {
    SpiffeId::new(id).expect("valid SPIFFE ID")
}

fn route(name: Option<&str>) -> Arc<Proxy> {
    let mut proxy = make_proxy("orders-route", "/api", Vec::new());
    proxy.namespace = "orders".to_string();
    proxy.name = name.map(str::to_string);
    Arc::new(proxy)
}

/// One request shape: how the context is prepared before the hooks run.
#[derive(Clone, Copy, Debug)]
enum Shape {
    InboundPeer,
    InboundNoPeer,
    InboundShortPeer,
    OutboundLocal,
    OutboundLocalNoRoute,
    OutboundNodeWaypointPeer,
    OutboundNodeWaypointNoPeer,
    UndirectedPeer,
    UndirectedLocal,
}

const SHAPES: [Shape; 9] = [
    Shape::InboundPeer,
    Shape::InboundNoPeer,
    Shape::InboundShortPeer,
    Shape::OutboundLocal,
    Shape::OutboundLocalNoRoute,
    Shape::OutboundNodeWaypointPeer,
    Shape::OutboundNodeWaypointNoPeer,
    Shape::UndirectedPeer,
    Shape::UndirectedLocal,
];

fn configs() -> Vec<Value> {
    vec![
        json!({}),
        json!({
            "namespace": "payments-config",
            "workload_spiffe_id": LOCAL_ID,
            "labels": {"app": "checkout", "service": "checkout-svc"}
        }),
        json!({"workload_spiffe_id": "spiffe://cluster.local/checkout-only"}),
        json!({"namespace": "plain", "labels": {"service.istio.io/canonical-name": "canon"}}),
    ]
}

fn context(shape: Shape, deferred: bool) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/api".into());
    if deferred {
        ctx = ctx.with_deferred_mesh_label_projection();
    }
    match shape {
        Shape::InboundPeer => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
            ctx.peer_spiffe_id = Some(spiffe(PEER_ID));
        }
        Shape::InboundNoPeer => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
        }
        Shape::InboundShortPeer => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Inbound);
            ctx.peer_spiffe_id = Some(spiffe(SHORT_PEER_ID));
        }
        Shape::OutboundLocal => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
            ctx.matched_proxy = Some(route(Some("orders")));
        }
        Shape::OutboundLocalNoRoute => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
        }
        Shape::OutboundNodeWaypointPeer => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
            ctx.node_waypoint_pod_uid = Some([7; 16]);
            ctx.peer_spiffe_id = Some(spiffe(PEER_ID));
            ctx.matched_proxy = Some(route(None));
        }
        Shape::OutboundNodeWaypointNoPeer => {
            ctx.mesh_direction = Some(MeshTrafficDirection::Outbound);
            ctx.node_waypoint_pod_uid = Some([7; 16]);
            ctx.matched_proxy = Some(route(Some("orders")));
        }
        Shape::UndirectedPeer => {
            ctx.peer_spiffe_id = Some(spiffe(PEER_ID));
            ctx.matched_proxy = Some(route(Some("orders")));
        }
        Shape::UndirectedLocal => {
            ctx.matched_proxy = Some(route(Some("orders")));
        }
    }
    ctx
}

async fn stamp(plugins: &[Arc<dyn Plugin>], ctx: &mut RequestContext) {
    for plugin in plugins {
        plugin.on_request_received(ctx).await;
    }
    let mut headers = HashMap::new();
    for plugin in plugins {
        plugin.before_proxy(ctx, &mut headers).await;
    }
}

fn label_keys() -> impl Iterator<Item = &'static str> {
    MeshLabel::ALL.into_iter().map(MeshLabel::key)
}

fn label_subset(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut labels: Vec<_> = label_keys()
        .filter_map(|key| {
            metadata
                .get(key)
                .map(|value| (key.to_string(), value.clone()))
        })
        .collect();
    labels.sort();
    labels
}

fn shadow_projection(ctx: &RequestContext) -> Vec<(String, String)> {
    let mut labels: Vec<_> = ctx
        .mesh_label_shadow()
        .expect("stamp allocates the shadow")
        .projection()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    labels.sort();
    labels
}

fn without_labels(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut rest: Vec<_> = metadata
        .iter()
        .filter(|(key, _)| !label_keys().any(|label| label == key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    rest.sort();
    rest
}

fn summary_for(ctx: &RequestContext) -> TransactionSummary {
    TransactionSummary {
        metadata: ctx.metadata.clone(),
        proxy_id: Some("orders-route".into()),
        response_status_code: 200,
        latency_total_ms: 4.0,
        ..Default::default()
    }
}

fn chain(config: &Value) -> Vec<Arc<dyn Plugin>> {
    vec![Arc::new(
        WorkloadMetrics::new(config).expect("workload_metrics config"),
    )]
}

#[tokio::test]
async fn shadow_equals_eager_projection_and_deferral_drops_only_labels() {
    for config in configs() {
        let plugins = chain(&config);
        for shape in SHAPES {
            let mut eager = context(shape, false);
            stamp(&plugins, &mut eager).await;
            let mut deferred = context(shape, true);
            stamp(&plugins, &mut deferred).await;

            assert_eq!(
                shadow_projection(&eager),
                label_subset(&eager.metadata),
                "{shape:?} {config}: shadow must mirror the eager label projection"
            );
            assert_eq!(
                eager.mesh_label_shadow(),
                deferred.mesh_label_shadow(),
                "{shape:?} {config}: deferral must not change the typed labels"
            );
            assert!(
                label_subset(&deferred.metadata).is_empty(),
                "{shape:?} {config}: a deferred request projects no label keys"
            );
            assert_eq!(
                without_labels(&eager.metadata),
                without_labels(&deferred.metadata),
                "{shape:?} {config}: deferral leaves every other key untouched"
            );
        }
    }
}

#[tokio::test]
async fn typed_metric_key_equals_string_parser_in_both_modes() {
    for config in configs() {
        let plugins = chain(&config);
        for shape in SHAPES {
            let mut eager = context(shape, false);
            stamp(&plugins, &mut eager).await;
            let mut deferred = context(shape, true);
            stamp(&plugins, &mut deferred).await;
            let eager_summary = summary_for(&eager);
            let expected = mesh_request_key(&eager_summary);
            assert!(expected.is_some(), "{shape:?} {config}");
            assert_eq!(
                mesh_request_key_for_request(&eager_summary, &eager),
                expected,
                "{shape:?} {config}: eager typed key"
            );
            assert_eq!(
                mesh_request_key_for_request(&summary_for(&deferred), &deferred),
                expected,
                "{shape:?} {config}: deferred typed key"
            );
        }
    }
}

#[tokio::test]
async fn eager_label_rewrites_fall_back_to_the_string_parser() {
    let plugins = chain(&configs()[1]);
    let rewrites: [fn(&mut MetadataMap); 4] = [
        |metadata| {
            metadata.insert("mesh.source.workload".into(), "rewritten".into());
        },
        |metadata| {
            metadata.remove("mesh.destination.service");
        },
        |metadata| {
            metadata.insert(
                "mesh.destination.principal".into(),
                "spiffe://cluster.local/ns/x/sa/y".into(),
            );
        },
        |metadata| {
            for key in label_keys() {
                metadata.remove(key);
            }
        },
    ];
    for shape in [Shape::InboundPeer, Shape::OutboundLocal] {
        for rewrite in rewrites {
            let mut ctx = context(shape, false);
            stamp(&plugins, &mut ctx).await;
            rewrite(&mut ctx.metadata);
            let summary = summary_for(&ctx);
            assert_eq!(
                mesh_request_key_for_request(&summary, &ctx),
                mesh_request_key(&summary),
                "{shape:?}: a rewritten label must be reported as the parser reads it"
            );
        }
    }
}

#[tokio::test]
async fn a_final_peer_with_fewer_spiffe_segments_keeps_no_stale_labels() {
    // Early trusted baggage asserts a namespaced identity; after header
    // transforms the baggage is gone and the namespace-less assertor is the
    // source. Neither projection may keep the asserted namespace or service
    // account.
    let plugins = chain(&json!({
        "namespace": "payments",
        "workload_spiffe_id": LOCAL_ID,
        "trusted_hbone_assertors": [{
            "assertor": SHORT_PEER_ID,
            "asserts": [PEER_ID]
        }]
    }));
    for deferred in [false, true] {
        let mut ctx = context(Shape::InboundShortPeer, deferred);
        ctx.metadata
            .insert("request_protocol".into(), "hbone".into());
        ctx.headers.insert(
            ferrum_edge::modes::mesh::hbone::BAGGAGE_HEADER.into(),
            "source.principal=spiffe%3A%2F%2Fcluster.local%2Fns%2Fstorefront%2Fsa%2Ffrontend"
                .into(),
        );
        for plugin in &plugins {
            plugin.on_request_received(&mut ctx).await;
        }
        let shadow = ctx.mesh_label_shadow().expect("shadow");
        assert_eq!(shadow.get(MeshLabel::SourcePrincipal), Some(PEER_ID));
        assert_eq!(shadow.get(MeshLabel::SourceNamespace), Some("storefront"));

        let mut headers = HashMap::new();
        for plugin in &plugins {
            plugin.before_proxy(&mut ctx, &mut headers).await;
        }
        let shadow = ctx.mesh_label_shadow().expect("shadow");
        assert_eq!(shadow.get(MeshLabel::SourcePrincipal), Some(SHORT_PEER_ID));
        assert_eq!(shadow.get(MeshLabel::SourceNamespace), None);
        assert_eq!(shadow.get(MeshLabel::SourceServiceAccount), None);
        assert_eq!(shadow.get(MeshLabel::SourceWorkload), Some("unknown"));
        if !deferred {
            assert_eq!(shadow_projection(&ctx), label_subset(&ctx.metadata));
            assert!(!ctx.metadata.contains_key("mesh.source.namespace"));
            assert!(!ctx.metadata.contains_key("mesh.source.service_account"));
        }
    }
}

#[tokio::test]
async fn gateway_mesh_dispatch_overlay_reaches_the_typed_projection() {
    let plugins = chain(&configs()[1]);
    let tags = HashMap::from([
        ("mesh.spiffe_id".to_string(), PEER_ID.to_string()),
        ("mesh.namespace".to_string(), "storefront".to_string()),
        ("mesh.service".to_string(), "frontend".to_string()),
        ("mesh.trust_domain".to_string(), "cluster.local".to_string()),
    ]);
    let mut eager = context(Shape::OutboundLocal, false);
    stamp(&plugins, &mut eager).await;
    let mut deferred = context(Shape::OutboundLocal, true);
    stamp(&plugins, &mut deferred).await;
    for ctx in [&mut eager, &mut deferred] {
        // What the dispatcher writes for a mesh-mTLS / HBONE target.
        for (tag, key) in [
            ("mesh.spiffe_id", "mesh.destination.principal"),
            ("mesh.namespace", "mesh.destination.namespace"),
            ("mesh.service", "mesh.destination.service"),
            ("mesh.trust_domain", "mesh.destination.trust_domain"),
        ] {
            ctx.metadata.insert(key.into(), tags[tag].clone());
        }
        ctx.metadata.insert(
            "mesh.connection_security_policy".into(),
            "mutual_tls".into(),
        );
        ctx.record_mesh_gateway_destination_overlay(&tags);
    }
    assert_eq!(shadow_projection(&eager), label_subset(&eager.metadata));
    assert_eq!(eager.mesh_label_shadow(), deferred.mesh_label_shadow());
    let eager_summary = summary_for(&eager);
    let expected = mesh_request_key(&eager_summary).expect("mesh key");
    assert_eq!(&*expected.destination_principal, PEER_ID);
    assert_eq!(&*expected.destination_service, "frontend");
    assert_eq!(&*expected.connection_security_policy, "mutual_tls");
    assert_eq!(
        mesh_request_key_for_request(&eager_summary, &eager).as_ref(),
        Some(&expected)
    );
    assert_eq!(
        mesh_request_key_for_request(&summary_for(&deferred), &deferred).as_ref(),
        Some(&expected)
    );
}

#[test]
fn the_dispatcher_overlay_and_both_entry_paths_stay_wired() {
    // Structural pins: the metadata overlay and its typed mirror live in one
    // function, and both request entry paths set the projection mode from
    // the same view before any plugin runs.
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let overlay = proxy
        .split("fn annotate_gateway_mesh_metadata(")
        .nth(1)
        .and_then(|body| body.split("\nfn ").next())
        .expect("annotate_gateway_mesh_metadata");
    assert!(overlay.contains("ctx.record_mesh_gateway_destination_overlay(&target.tags);"));
    for source in [proxy, include_str!("../../../src/http3/server.rs")] {
        let digest = source
            .find("ctx.set_response_presentation_policy_digest(")
            .expect("presentation digest site");
        let mode = source
            .find("ctx.set_mesh_label_projection_deferred(")
            .expect("projection mode site");
        let first_hook = source
            .find("plugin.on_request_received(&mut ctx)")
            .expect("first request hook");
        assert!(digest < mode && mode < first_hook);
    }
}

#[tokio::test]
async fn compatibility_clones_carry_the_typed_projection() {
    let plugins = chain(&configs()[1]);
    let mut ctx = context(Shape::InboundPeer, true);
    stamp(&plugins, &mut ctx).await;
    let clone = ctx.clone();
    assert!(clone.mesh_label_projection_deferred());
    assert_eq!(clone.mesh_label_shadow(), ctx.mesh_label_shadow());
}

struct CustomObserver;

#[async_trait]
impl Plugin for CustomObserver {
    fn name(&self) -> &str {
        "custom_label_observer"
    }
}

fn view_defers(plugins: Vec<(&str, &str, Value)>) -> bool {
    let instances = plugins
        .into_iter()
        .map(|(id, name, config)| {
            make_plugin_config_with_json(id, name, config, PluginScope::Global, None)
        })
        .collect();
    let cache = PluginCache::new(&GatewayConfig {
        proxies: vec![make_proxy("p1", "/api", Vec::new())],
        plugin_configs: instances,
        ..Default::default()
    })
    .expect("plugin chain");
    ferrum_edge::_test_support::request_view_capabilities_for_test(
        &cache,
        "ferrum",
        "p1",
        ProxyProtocol::Http,
    )
    .has(PluginCapabilities::MESH_LABEL_PROJECTION_DEFERRABLE)
}

#[tokio::test]
async fn only_views_of_audited_non_observers_defer_the_projection() {
    let mesh_chain = || {
        vec![
            ("sid", "spiffe_identity", json!({})),
            ("authz", "mesh_authz", json!({})),
            ("wm", "workload_metrics", json!({})),
        ]
    };
    assert!(view_defers(mesh_chain()));

    let mut with_log = mesh_chain();
    with_log.push(("log", "stdout_logging", json!({})));
    assert!(!view_defers(with_log));

    let mut with_prometheus = mesh_chain();
    with_prometheus.push(("prom", "prometheus_metrics", json!({})));
    assert!(!view_defers(with_prometheus));

    let mut exporting = mesh_chain();
    exporting[2].2 = json!({
        "allow_plaintext": true,
        "tracing_provider": {
            "kind": "zipkin",
            "config": {"url": "http://zipkin:9411/api/v2/spans"}
        }
    });
    assert!(!view_defers(exporting));

    let mut propagation_only = mesh_chain();
    propagation_only[2].2 = json!({"sampling_percentage": 100.0});
    assert!(view_defers(propagation_only));

    for name in ["spiffe_identity", "mesh_authz", "workload_metrics"] {
        let plugin = create_plugin(name, &json!({}))
            .expect("built-in config")
            .expect("built-in plugin");
        assert!(!plugin.observes_mesh_label_metadata(), "{name}");
    }
    // Anything unaudited — every custom plugin — keeps the eager projection.
    assert!(CustomObserver.observes_mesh_label_metadata());
}

#[tokio::test]
async fn service_graph_records_one_edge_for_eager_and_deferred_requests() {
    let unique = format!("label-projection-{}", uuid::Uuid::new_v4());
    let plugins = chain(&json!({
        "namespace": "payments",
        "workload_spiffe_id": LOCAL_ID,
        "labels": {"app": unique}
    }));
    for deferred in [false, true] {
        let mut ctx = context(Shape::InboundPeer, deferred);
        stamp(&plugins, &mut ctx).await;
        log_with_mirror(&plugins, &summary_for(&ctx), &ctx).await;
    }
    let edge = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let snapshot = global_service_graph().snapshot();
            if let Some(edge) = snapshot
                .edges
                .iter()
                .find(|edge| edge.destination_workload == unique)
                .filter(|edge| edge.requests_total == 2)
            {
                break edge.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one service-graph edge for both requests");
    assert_eq!(edge.source_principal, PEER_ID);
    assert_eq!(edge.source_workload, "frontend");
    assert_eq!(edge.destination_principal, LOCAL_ID);
    assert_eq!(edge.destination_namespace, "payments");
}
