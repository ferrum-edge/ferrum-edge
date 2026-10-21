//! Allocation requests and semantic parity for the production terminal projection.
//!
//! The allocator already installed by `response_coalescing_allocation_tests`
//! forwards unchanged to System and counts only this thread. Setup, async hooks,
//! assertions, formatting and drops all stay outside each synchronous window.
//! These counts describe Rust allocation requests, not RSS or throughput.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use ferrum_edge::_test_support::{
    clone_log_metadata_for_test, request_upload_auth_deadline_for_test,
    set_diagnostic_slot_for_test, set_request_credential_deadline_for_test,
    set_request_http_flavor_for_test, set_waf_metadata_for_test,
    take_terminal_log_metadata_for_test,
};
use ferrum_edge::PluginCache;
use ferrum_edge::config::types::{GatewayConfig, HttpFlavor, PluginScope};
use ferrum_edge::diagnostic_ref::DiagnosticSlot;
use ferrum_edge::identity::SpiffeId;
use ferrum_edge::modes::mesh::MeshTrafficDirection;
use ferrum_edge::plugins::api_chargeback::{ProtocolFamily, global_registry};
use ferrum_edge::plugins::correlation_id::CorrelationId;
use ferrum_edge::plugins::mesh::workload_metrics::WorkloadMetrics;
use ferrum_edge::plugins::trigger::{PluginTriggerGate, TriggerPhase};
use ferrum_edge::plugins::{
    MirrorResponseMeta, Plugin, PluginResult, RequestContext, ResponseDelivery, TransactionSummary,
    log_with_mirror,
};
use ferrum_edge::proxy::auth_lifetime::StreamAuthTermination;
use ferrum_edge::proxy::deferred_log::{BodyOutcome, DeferredTransactionLogger};
use serde_json::json;

use super::response_coalescing_allocation_tests::measure;
use crate::unit::env_lock::EnvGuard;
use crate::unit::plugins::plugin_utils::{
    create_test_proxy, make_plugin_config_with_json, make_proxy,
};

const RETAINED_KEY: &str = "mesh.source.principal";

async fn mesh_context(direction: MeshTrafficDirection, cel: bool) -> RequestContext {
    let mut config = json!({
        "node_id": "spiffe://cluster.local/ns/ferrum/sa/svc",
        "topology": "sidecar",
        "namespace": "ferrum",
        "workload_spiffe_id": "spiffe://cluster.local/ns/ferrum/sa/svc",
        "labels": {"app": "svc"}
    });
    if cel {
        config["metrics"] = json!({
            "disabled_metrics": ["REQUEST_DURATION"],
            "tag_overrides": [{
                "metric": "REQUEST_COUNT",
                "name": "source_workload",
                "operation": {"type": "set_expr", "cel": "request.host"}
            }, {
                "metric": "REQUEST_COUNT",
                "name": "destination_service",
                "operation": {"type": "set_expr", "cel": "string(destination.port)"}
            }]
        });
    }
    let metrics = WorkloadMetrics::new(&config).expect("real mesh metrics fixture");
    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/checkout".into());
    ctx.mesh_direction = Some(direction);
    ctx.peer_spiffe_id =
        Some(SpiffeId::new("spiffe://cluster.local/ns/ferrum/sa/client").expect("peer identity"));
    ctx.request_authority = Some("svc.ferrum.svc.cluster.local".into());
    ctx.mesh_outbound_destination_authz_port = Some(18080);
    let mut proxy = create_test_proxy();
    proxy.namespace = "ferrum".into();
    proxy.name = Some("svc".into());
    ctx.matched_proxy = Some(Arc::new(proxy));
    assert!(matches!(
        metrics.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    let mut headers = std::mem::take(&mut ctx.headers);
    assert!(matches!(
        metrics.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx.headers = headers;
    assert!(matches!(
        metrics
            .after_proxy(&mut ctx, 200, &mut HashMap::new())
            .await,
        PluginResult::Continue
    ));
    ctx
}

fn compare_projection_allocations(label: &str, ctx: &RequestContext) -> (usize, usize) {
    // Exercise the real code once on this thread before opening either window.
    drop(clone_log_metadata_for_test(ctx));
    let mut warm = ctx.clone();
    drop(take_terminal_log_metadata_for_test(&mut warm));
    let mut owned_ctx = ctx.clone();
    let original_metadata = ctx.metadata.clone();
    let retained_ptr = owned_ctx.metadata.get(RETAINED_KEY).map(|v| v.as_ptr());

    let ((clone_count, clone_bytes), cloned) = measure(|| clone_log_metadata_for_test(ctx));
    let ((owned_count, owned_bytes), owned) =
        measure(|| take_terminal_log_metadata_for_test(&mut owned_ctx));

    assert_eq!(owned, cloned, "{label}: complete projected metadata parity");
    assert_eq!(
        ctx.metadata, original_metadata,
        "borrowed path stays intact"
    );
    assert!(
        owned_ctx.metadata.is_empty(),
        "owned path transfers the map"
    );
    if let Some(pointer) = retained_ptr {
        assert_eq!(
            owned[RETAINED_KEY].as_ptr(),
            pointer,
            "retained string moves"
        );
    }
    println!(
        "terminal_metadata_projection {label}: input_keys={} output_keys={} clone_allocations={clone_count} clone_bytes={clone_bytes} owned_allocations={owned_count} owned_bytes={owned_bytes}",
        ctx.metadata.len(),
        owned.len()
    );
    if !ctx.metadata.is_empty() {
        assert!(
            owned_count < clone_count,
            "{label}: avoid the metadata clone"
        );
        assert!(owned_bytes < clone_bytes, "{label}: avoid cloned storage");
    }
    (owned_count, owned_bytes)
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_metadata_projection_moves_real_mesh_maps_without_allocating() {
    let _env = EnvGuard::new(&[]);
    for (label, direction, cel) in [
        ("inbound", MeshTrafficDirection::Inbound, false),
        ("outbound", MeshTrafficDirection::Outbound, false),
        ("outbound_cel", MeshTrafficDirection::Outbound, true),
    ] {
        let ctx = mesh_context(direction, cel).await;
        assert!(ctx.metadata.contains_key(RETAINED_KEY));
        if cel {
            assert!(
                ctx.metadata
                    .contains_key("mesh.metrics.request_count.tag_overrides")
            );
            assert_eq!(
                ctx.metadata["mesh.metrics.cel.request_host"],
                "svc.ferrum.svc.cluster.local"
            );
            assert_eq!(ctx.metadata["mesh.metrics.cel.destination_port"], "18080");
        }
        assert_eq!(compare_projection_allocations(label, &ctx), (0, 0));
    }
}

#[test]
fn terminal_metadata_projection_empty_context_needs_no_allocation() {
    let ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
    assert_eq!(compare_projection_allocations("empty", &ctx), (0, 0));
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_metadata_projection_preserves_owned_fields_and_redaction() {
    let _env = EnvGuard::new(&[]);
    let mut ctx = mesh_context(MeshTrafficDirection::Inbound, true).await;
    ctx.headers
        .insert("x-request-id".into(), "projection-correlation".into());
    let correlation = CorrelationId::new(&json!({})).expect("correlation fixture");
    assert!(matches!(
        correlation.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    ctx.metadata.insert("request_id".into(), "spoofed".into());
    ctx.metadata.insert(
        "correlation_id.instance.x-request-id".into(),
        "spoofed".into(),
    );
    set_waf_metadata_for_test(&mut ctx, "waf.scan_truncated", "true");
    for (key, value) in [
        ("waf.scan_truncated", "spoofed"),
        ("waf.forged", "spoofed"),
        ("request_body", "private body"),
        ("_dedup_key", "private coordination"),
        ("grpc_web.request_trailers", "private trailers"),
        ("sse:last_event_id", "private resume state"),
        ("ai_tool_governor.stream_requested", "true"),
        ("mcp.needs_response_rewrite", "true"),
        ("authorization.termination_reason", "spoofed"),
        ("custom.retained", "custom observer value"),
    ] {
        ctx.metadata.insert(key.into(), value.into());
    }
    ctx.authenticated_identity = Some("spiffe://cluster.local/ns/ferrum/sa/client".into());
    set_request_credential_deadline_for_test(
        &mut ctx,
        Some(tokio::time::Instant::now() + Duration::from_secs(60)),
    );
    let (_, family, latch) = request_upload_auth_deadline_for_test(&ctx, 300)
        .expect("authenticated request has an upload lifetime plan");
    assert!(latch.record_once(StreamAuthTermination::CredentialExpired, family));

    compare_projection_allocations("typed_ownership_and_redaction", &ctx);
    let projected = take_terminal_log_metadata_for_test(&mut ctx);
    assert_eq!(projected["request_id"], "projection-correlation");
    assert_eq!(
        projected["correlation_id.instance.x-request-id"],
        "projection-correlation"
    );
    assert_eq!(projected["waf.scan_truncated"], "true");
    assert_eq!(
        projected["authorization.termination_reason"],
        "credential_expired"
    );
    assert_eq!(projected["custom.retained"], "custom observer value");
    assert_eq!(projected["sse:leid_present"], "1");
    assert_eq!(projected["sse:leid_bytes"], "20");
    for absent in [
        "request_body",
        "_dedup_key",
        "waf.forged",
        "grpc_web.request_trailers",
        "sse:last_event_id",
        "ai_tool_governor.stream_requested",
        "mcp.needs_response_rewrite",
    ] {
        assert!(!projected.contains_key(absent), "must omit {absent}");
    }
    assert!(projected.contains_key("mesh.metrics.request_count.tag_overrides"));
    // Taking the public map does not consume any authoritative owner.
    let reprojection = clone_log_metadata_for_test(&ctx);
    for key in [
        "request_id",
        "correlation_id.instance.x-request-id",
        "waf.scan_truncated",
        "authorization.termination_reason",
    ] {
        assert_eq!(reprojection.get(key), projected.get(key));
    }
}

struct TerminalProbe {
    label: &'static str,
    gate: Option<Arc<PluginTriggerGate>>,
    tx: tokio::sync::mpsc::UnboundedSender<Capture>,
}

#[async_trait]
impl Plugin for TerminalProbe {
    fn name(&self) -> &str {
        "terminal_metadata_probe"
    }
    fn priority(&self) -> u16 {
        100
    }

    fn defers_response_stream_termination_until_after_peers(&self) -> bool {
        self.label == "second"
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _outcome: &BodyOutcome,
    ) {
        assert!(
            ctx.metadata.contains_key(RETAINED_KEY),
            "map survives through the final hook"
        );
        if self.label == "second" {
            assert_eq!(ctx.metadata["stream.first"], "finalized");
        }
        ctx.metadata
            .insert(format!("stream.{}", self.label), "finalized".into());
    }

    async fn log(&self, summary: &TransactionSummary) {
        let pointer = summary.metadata[RETAINED_KEY].as_ptr() as usize;
        let decision = self
            .gate
            .as_ref()
            .map(|gate| gate.transaction_log_decision_or_run(summary));
        self.tx
            .send((self.label.into(), summary.clone(), pointer, decision))
            .expect("capture receiver");
    }
}

type Capture = (String, TransactionSummary, usize, Option<bool>);

async fn receive(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Capture>) -> Capture {
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("terminal delivery completed")
        .expect("capture channel remains open")
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_metadata_projection_deferred_hooks_keep_order_and_move_final_strings() {
    ferrum_edge::observability_delivery::begin_serving_cycle();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(
        // Place the deferred hook first so a single chain-order pass would
        // fail its assertion that the ordinary peer already finalized metadata.
        ["second", "first"]
            .into_iter()
            .map(|label| {
                Arc::new(TerminalProbe {
                    label,
                    gate: None,
                    tx: tx.clone(),
                }) as Arc<dyn Plugin>
            })
            .collect(),
    );
    let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), "/".into());
    ctx.metadata.insert(
        RETAINED_KEY.into(),
        "spiffe://cluster.local/ns/ferrum/sa/client".into(),
    );
    ctx.metadata.insert("request_body".into(), "private".into());
    let pointer = ctx.metadata[RETAINED_KEY].as_ptr() as usize;
    let logger = DeferredTransactionLogger::new(TransactionSummary::default(), plugins, ctx);
    logger.fire(BodyOutcome::success(77));
    logger.fire(BodyOutcome::success(88));
    drop(logger);
    // Deferral applies only to termination hooks. Log hooks keep chain order.
    for label in ["second", "first"] {
        let (observed_label, summary, observed_pointer, _) = receive(&mut rx).await;
        assert_eq!(observed_label, label);
        assert_eq!(
            observed_pointer, pointer,
            "the actual deferred path moves string storage"
        );
        assert_eq!(summary.metadata["stream.first"], "finalized");
        assert_eq!(summary.metadata["stream.second"], "finalized");
        assert!(!summary.metadata.contains_key("request_body"));
        assert_eq!(summary.bytes_received, 77);
        assert_eq!(summary.response_delivery, ResponseDelivery::Observed);
    }
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty
            | tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_metadata_projection_preserves_terminal_typed_state_and_mirrors() {
    ferrum_edge::observability_delivery::begin_serving_cycle();
    for websocket in [false, true] {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new(
            PluginTriggerGate::compile(
                &serde_json::from_value(
                    json!({"when": {"match": {"path": {"prefix": ["/selected"]}}}}),
                )
                .expect("trigger schema"),
                "terminal-projection-gate",
            )
            .expect("trigger compiles"),
        );
        let mut ctx = RequestContext::new(
            "10.0.0.2".into(),
            if websocket { "GET" } else { "HEAD" }.into(),
            "/not-selected".into(),
        );
        ctx.metadata.insert(
            RETAINED_KEY.into(),
            "spiffe://cluster.local/ns/ferrum/sa/client".into(),
        );
        assert!(!gate.admits_request(&mut ctx, TriggerPhase::PreAuth));
        if websocket {
            set_request_http_flavor_for_test(&mut ctx, HttpFlavor::WebSocket);
        }
        let slot = DiagnosticSlot::shared();
        set_diagnostic_slot_for_test(&mut ctx, Arc::clone(&slot));
        let (mirror_tx, mirror_rx) = tokio::sync::watch::channel(None);
        ctx.mirror_result_rxs.push(mirror_rx);
        mirror_tx
            .send(Some(MirrorResponseMeta {
                mirror_plugin_id: Some("mirror-projection".into()),
                mirror_target_url: "http://mirror.test/".into(),
                mirror_response_status_code: Some(202),
                mirror_response_size_bytes: Some(9),
                mirror_response_advertised_size_bytes: Some(9),
                mirror_latency_ms: 1.0,
                mirror_error: None,
            }))
            .expect("mirror receiver");
        let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(TerminalProbe {
            label: "first",
            gate: Some(gate),
            tx,
        })]);
        let summary = TransactionSummary {
            response_status_code: 503,
            ..TransactionSummary::default()
        };
        let logger = DeferredTransactionLogger::new(summary, plugins, ctx);
        logger.fire(BodyOutcome::success(77));
        let (_, primary, _, decision) = receive(&mut rx).await;
        assert!(!primary.mirror);
        assert_eq!(primary.response_delivery, ResponseDelivery::Observed);
        assert_eq!(
            decision,
            Some(false),
            "typed skip survives the owned projection"
        );
        assert_eq!(primary.bytes_received, if websocket { 77 } else { 0 });
        if websocket {
            assert_eq!(primary.metadata["request_protocol"], "ws");
        }
        assert!(
            slot.detail().is_some(),
            "diagnostic consumer still records the terminal"
        );
        let (_, mirrored, _, mirror_decision) = receive(&mut rx).await;
        assert!(mirrored.mirror);
        assert_eq!(mirrored.response_delivery, ResponseDelivery::NotObserved);
        assert_eq!(mirrored.response_status_code, 202);
        assert_eq!(
            mirrored.metadata[RETAINED_KEY],
            primary.metadata[RETAINED_KEY]
        );
        assert_eq!(mirror_decision, Some(false));
    }
}

struct ParkingTerminalLog {
    primary_calls: Arc<AtomicUsize>,
    mirror_calls: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl Plugin for ParkingTerminalLog {
    fn name(&self) -> &str {
        "terminal_metadata_parking"
    }

    fn priority(&self) -> u16 {
        100
    }

    async fn log(&self, summary: &TransactionSummary) {
        if summary.mirror {
            self.mirror_calls.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.primary_calls.fetch_add(1, Ordering::Relaxed);
        self.started.notify_one();
        std::future::pending::<()>().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_metadata_projection_cancelled_log_keeps_owned_summary_and_mirror() {
    let _env = EnvGuard::new(&[]);
    ferrum_edge::observability_delivery::begin_serving_cycle();
    let mut ctx = mesh_context(MeshTrafficDirection::Inbound, true).await;
    ctx.metadata.insert("request_body".into(), "private".into());
    ctx.metadata
        .insert("custom.retained".into(), "observer value".into());
    let expected_metadata = clone_log_metadata_for_test(&ctx);
    let (mirror_tx, mirror_rx) = tokio::sync::watch::channel(None);
    ctx.mirror_result_rxs.push(mirror_rx);
    let summary = TransactionSummary {
        response_status_code: 201,
        response_delivery: ResponseDelivery::Observed,
        metadata: take_terminal_log_metadata_for_test(&mut ctx),
        ..TransactionSummary::default()
    };
    assert!(ctx.metadata.is_empty());
    let ctx = Arc::new(ctx);
    let primary_calls = Arc::new(AtomicUsize::new(0));
    let mirror_calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(ParkingTerminalLog {
            primary_calls: Arc::clone(&primary_calls),
            mirror_calls: Arc::clone(&mirror_calls),
            started: Arc::clone(&started),
        }),
        Arc::new(TerminalProbe {
            label: "survivor",
            gate: None,
            tx,
        }),
    ];

    // The production deferred boundary is covered above. Exercise its owned
    // projection followed by the actual cancellation-safe log funnel here,
    // with a task we can cancel without stopping the global delivery lifecycle.
    let task_ctx = Arc::clone(&ctx);
    let handler = tokio::spawn(async move {
        log_with_mirror(&plugins, &summary, &task_ctx).await;
    });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .expect("primary sink started");
    assert!(ctx.terminal_record_started());
    drop(ctx);
    handler.abort();
    assert!(
        handler
            .await
            .expect_err("log task cancelled")
            .is_cancelled()
    );

    let (_, primary, _, _) = receive(&mut rx).await;
    assert!(!primary.mirror);
    assert_eq!(primary.response_status_code, 201);
    assert_eq!(primary.response_delivery, ResponseDelivery::Observed);
    assert_eq!(primary.metadata, expected_metadata);
    // Publish only after cancellation and resumed primary delivery, so the
    // continuation must retain its cloned context's pending mirror receiver.
    mirror_tx
        .send(Some(MirrorResponseMeta {
            mirror_plugin_id: Some("cancelled-projection-mirror".into()),
            mirror_target_url: "http://mirror.test/".into(),
            mirror_response_status_code: Some(202),
            mirror_response_size_bytes: Some(9),
            mirror_response_advertised_size_bytes: Some(9),
            mirror_latency_ms: 1.0,
            mirror_error: None,
        }))
        .expect("mirror receiver");
    let (_, mirrored, _, _) = receive(&mut rx).await;
    assert!(mirrored.mirror);
    assert_eq!(mirrored.response_status_code, 202);
    assert_eq!(mirrored.response_delivery, ResponseDelivery::NotObserved);
    assert_eq!(
        mirrored.metadata[RETAINED_KEY],
        primary.metadata[RETAINED_KEY]
    );
    assert_eq!(mirrored.metadata["custom.retained"], "observer value");
    assert!(!mirrored.metadata.contains_key("request_body"));
    assert_eq!(primary_calls.load(Ordering::Relaxed), 1);
    assert_eq!(mirror_calls.load(Ordering::Relaxed), 1);
    assert!(matches!(
        rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty
            | tokio::sync::mpsc::error::TryRecvError::Disconnected)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_metadata_projection_real_wrapper_suppresses_only_the_skipped_log() {
    let _env = EnvGuard::new(&[]);
    ferrum_edge::observability_delivery::begin_serving_cycle();
    let proxy_id = "terminal-projection-trigger-wrapper";
    let mut bill = make_plugin_config_with_json(
        "projection-bill",
        "api_chargeback",
        json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}]}),
        PluginScope::Proxy,
        Some(proxy_id),
    );
    bill.trigger = Some(
        serde_json::from_value(json!({
            "when": {"match": {"path": {"prefix": ["/selected"]}}}
        }))
        .expect("trigger schema"),
    );
    // Keep the published wrapper before the completion probe in every phase.
    bill.priority_override = Some(99);
    let config = GatewayConfig {
        version: "1".into(),
        proxies: vec![make_proxy(proxy_id, "/", vec!["projection-bill"])],
        plugin_configs: vec![bill],
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&config).expect("real trigger-wrapped chargeback fixture");
    let published = cache.get_plugins("ferrum", proxy_id);
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].name(), "api_chargeback");

    for (consumer, initial_path, final_path, expected_calls) in [
        ("terminal-projection-skipped", "/free", "/selected/later", 0),
        (
            "terminal-projection-admitted",
            "/selected/first",
            "/free/later",
            1,
        ),
    ] {
        let calls = || -> u64 {
            global_registry()
                .entries
                .iter()
                .filter(|entry| {
                    entry.consumer.as_ref() == consumer
                        && entry.proxy_id.as_ref() == proxy_id
                        && entry.protocol_family == ProtocolFamily::Http
                })
                .map(|entry| entry.call_count.load(Ordering::Relaxed))
                .sum()
        };
        assert_eq!(calls(), 0, "the fixture owns a fresh billing identity");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut plugins = published.as_ref().clone();
        plugins.push(Arc::new(TerminalProbe {
            label: "first",
            gate: None,
            tx,
        }));
        assert!(
            plugins
                .windows(2)
                .all(|pair| pair[0].priority() <= pair[1].priority())
        );
        let mut ctx = RequestContext::new("10.0.0.2".into(), "GET".into(), initial_path.into());
        ctx.metadata.insert(
            RETAINED_KEY.into(),
            "spiffe://cluster.local/ns/ferrum/sa/client".into(),
        );
        for plugin in &plugins {
            assert!(matches!(
                plugin.on_request_received(&mut ctx).await,
                PluginResult::Continue
            ));
        }
        let mut headers = HashMap::new();
        for plugin in &plugins {
            assert!(matches!(
                plugin.before_proxy(&mut ctx, &mut headers).await,
                PluginResult::Continue
            ));
        }
        // Terminal dispatch must use the wrapper's memoized decision, even
        // when later request mutations would reverse the original predicate.
        ctx.path = final_path.into();
        let summary = TransactionSummary {
            namespace: "ferrum".into(),
            consumer_username: Some(consumer.into()),
            http_method: "GET".into(),
            request_path: final_path.into(),
            proxy_id: Some(proxy_id.into()),
            response_status_code: 200,
            ..TransactionSummary::default()
        };
        let logger = DeferredTransactionLogger::new(summary, Arc::new(plugins), ctx);
        logger.fire(BodyOutcome::success(77));
        let (label, observed, _, _) = receive(&mut rx).await;
        assert_eq!(
            label, "first",
            "the trailing observer confirms dispatch completed"
        );
        assert_eq!(observed.metadata["stream.first"], "finalized");
        assert_eq!(
            calls(),
            expected_calls,
            "the real wrapper must govern the inner log hook"
        );
    }
}
