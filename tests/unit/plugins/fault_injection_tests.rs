//! Tests for fault_injection plugin

use ferrum_edge::plugins::fault_injection::FaultInjectionPlugin;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use serde_json::json;
use std::collections::HashMap;

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

async fn run_before_proxy(plugin: &FaultInjectionPlugin, ctx: &mut RequestContext) -> PluginResult {
    let mut headers = HashMap::new();
    plugin.before_proxy(ctx, &mut headers).await
}

// === Config validation ===

#[test]
fn test_valid_abort_only() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0 }
    }));
    assert!(plugin.is_ok());
    let p = plugin.unwrap();
    assert_eq!(p.name(), "fault_injection");
    assert_eq!(
        p.priority(),
        ferrum_edge::plugins::priority::FAULT_INJECTION
    );
}

#[test]
fn test_valid_delay_only() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 100, "percentage": 25.0 }
    }));
    assert!(plugin.is_ok());
}

#[test]
fn test_valid_abort_and_delay() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 500, "percentage": 10.0 },
        "delay": { "duration_ms": 200, "percentage": 30.0 }
    }));
    assert!(plugin.is_ok());
}

#[test]
fn test_valid_abort_with_body() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "body": "service down" }
    }));
    assert!(plugin.is_ok());
}

#[test]
fn test_valid_abort_with_grpc_status() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "grpc_status": 14 }
    }));
    assert!(plugin.is_ok());
}

#[test]
fn test_reject_no_abort_no_delay() {
    let err = FaultInjectionPlugin::new(&json!({})).err().unwrap();
    assert!(err.contains("at least one of 'abort' or 'delay'"));
}

#[test]
fn test_reject_both_null() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": null,
        "delay": null
    }))
    .err()
    .unwrap();
    assert!(err.contains("at least one of 'abort' or 'delay'"));
}

#[test]
fn test_reject_non_object_config() {
    let err = FaultInjectionPlugin::new(&json!("bad")).err().unwrap();
    assert!(err.contains("config must be an object"));
}

#[test]
fn test_reject_unknown_top_level_field() {
    let err = FaultInjectionPlugin::new(&json!({
        "deplay": { "duration_ms": 10, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("unknown config field"));
}

#[test]
fn test_reject_unknown_abort_field() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0, "why": "test" }
    }))
    .err()
    .unwrap();
    assert!(err.contains("unknown abort field"));
}

#[test]
fn test_reject_percentage_over_100() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 500, "percentage": 101.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be 0.0-100.0"));
}

#[test]
fn test_reject_percentage_negative() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 100, "percentage": -1.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be 0.0-100.0"));
}

#[test]
fn test_reject_status_code_zero() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 0, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be 200-599"));
}

#[test]
fn test_reject_status_code_100() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 100, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be 200-599"));
}

#[test]
fn test_reject_status_code_600() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 600, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be 200-599"));
}

#[test]
fn test_reject_duration_ms_zero() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 0, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be greater than 0"));
}

#[test]
fn test_reject_duration_ms_above_cap() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 3_600_001_u64, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("duration_ms must be <="));
}

#[test]
fn test_reject_zero_abort_percentage() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 0.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be greater than 0.0"));
}

#[test]
fn test_reject_zero_delay_percentage() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 100, "percentage": 0.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be greater than 0.0"));
}

#[test]
fn test_reject_grpc_status_17() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0, "grpc_status": 17 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("must be 0-16"));
}

#[test]
fn test_reject_abort_not_object() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": "bad"
    }))
    .err()
    .unwrap();
    assert!(err.contains("'abort' must be an object"));
}

#[test]
fn test_reject_delay_not_object() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": 42
    }))
    .err()
    .unwrap();
    assert!(err.contains("'delay' must be an object"));
}

#[test]
fn test_reject_abort_body_not_string() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0, "body": 42 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("body must be a string"));
}

#[test]
fn test_reject_missing_abort_percentage() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("percentage") && err.contains("required"));
}

#[test]
fn test_reject_missing_delay_percentage() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 100 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("percentage") && err.contains("required"));
}

#[test]
fn test_reject_missing_abort_status_code() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("status_code"));
}

#[test]
fn test_reject_missing_delay_duration_ms() {
    let err = FaultInjectionPlugin::new(&json!({
        "delay": { "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("duration_ms"));
}

// === Behavior tests ===

#[tokio::test]
async fn test_100_percent_abort_always_triggers() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();

    for _ in 0..20 {
        let mut ctx = make_ctx();
        let result = run_before_proxy(&plugin, &mut ctx).await;
        match result {
            PluginResult::Reject { status_code, .. } => {
                assert_eq!(status_code, 503);
            }
            _ => panic!("expected Reject"),
        }
        assert_eq!(ctx.metadata.get("fault_injected").unwrap(), "true");
        assert_eq!(ctx.metadata.get("fault_type").unwrap(), "abort");
        assert_eq!(ctx.metadata.get("fault_abort_status").unwrap(), "503");
    }
}

#[tokio::test]
async fn test_100_percent_delay_always_triggers() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 1, "percentage": 100.0 }
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let start = std::time::Instant::now();
    let result = run_before_proxy(&plugin, &mut ctx).await;
    let elapsed = start.elapsed();

    assert!(matches!(result, PluginResult::Continue));
    assert!(elapsed.as_millis() >= 1);
    assert_eq!(ctx.metadata.get("fault_injected").unwrap(), "true");
    assert_eq!(ctx.metadata.get("fault_type").unwrap(), "delay");
    assert_eq!(ctx.metadata.get("fault_delay_ms").unwrap(), "1");
}

#[tokio::test]
async fn test_delay_then_abort_both_100_percent() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 500, "percentage": 100.0, "body": "injected fault" },
        "delay": { "duration_ms": 1, "percentage": 100.0 }
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let start = std::time::Instant::now();
    let result = run_before_proxy(&plugin, &mut ctx).await;
    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() >= 1);

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 500);
            assert_eq!(body, "injected fault");
        }
        _ => panic!("expected Reject"),
    }

    assert_eq!(ctx.metadata.get("fault_injected").unwrap(), "true");
    assert_eq!(ctx.metadata.get("fault_type").unwrap(), "delay_and_abort");
    assert_eq!(ctx.metadata.get("fault_delay_ms").unwrap(), "1");
    assert_eq!(ctx.metadata.get("fault_abort_status").unwrap(), "500");
}

#[tokio::test]
async fn test_abort_with_empty_body() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 429, "percentage": 100.0 }
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let result = run_before_proxy(&plugin, &mut ctx).await;

    match result {
        PluginResult::Reject { body, .. } => {
            assert!(body.is_empty());
        }
        _ => panic!("expected Reject"),
    }
}

#[test]
fn test_supported_protocols() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();
    assert_eq!(
        plugin.supported_protocols(),
        &[
            ferrum_edge::plugins::ProxyProtocol::Http,
            ferrum_edge::plugins::ProxyProtocol::Grpc,
            ferrum_edge::plugins::ProxyProtocol::WebSocket,
            ferrum_edge::plugins::ProxyProtocol::Tcp,
        ]
    );
}

#[test]
fn test_boundary_percentage_100() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }));
    assert!(plugin.is_ok());
}

#[test]
fn test_boundary_status_code_599() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 599, "percentage": 50.0 }
    }));
    assert!(plugin.is_ok());
}

#[tokio::test]
async fn test_abort_injects_grpc_status_header() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "grpc_status": 2 }
    }))
    .unwrap();

    let mut ctx = make_ctx();
    let result = run_before_proxy(&plugin, &mut ctx).await;

    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("grpc-status").unwrap(), "2");
        }
        _ => panic!("expected Reject"),
    }
}

#[test]
fn test_grpc_status_0_valid() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0, "grpc_status": 0 }
    }));
    assert!(plugin.is_ok());
}

#[test]
fn test_grpc_status_16_valid() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0, "grpc_status": 16 }
    }));
    assert!(plugin.is_ok());
}

#[tokio::test]
async fn test_stream_connect_abort_100_percent() {
    use ferrum_edge::config::types::BackendScheme;
    use ferrum_edge::consumer_index::ConsumerIndex;
    use ferrum_edge::plugins::StreamConnectionContext;
    use std::sync::Arc;

    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "body": "stream fault" }
    }))
    .unwrap();

    let mut ctx = StreamConnectionContext {
        client_ip: "127.0.0.1".to_string(),
        direct_client_ip: "127.0.0.1".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: None,
        listen_port: 9000,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: Arc::new(ConsumerIndex::new(&[])),
        identified_consumer: None,
        authenticated_identity: None,
        auth_method: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
        mesh_direction: None,
        node_waypoint_policy_scope: None,
        first_bytes: None,
        first_bytes_kind: None,
    };

    let result = plugin.on_stream_connect(&mut ctx).await;

    match result {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 503);
            assert!(body.is_empty());
        }
        _ => panic!("expected Reject for stream connect"),
    }

    let metadata = ctx.take_metadata();
    assert_eq!(metadata.get("fault_injected").unwrap(), "true");
    assert_eq!(metadata.get("fault_type").unwrap(), "abort");
}

#[tokio::test]
async fn test_stream_connect_delay_100_percent() {
    use ferrum_edge::config::types::BackendScheme;
    use ferrum_edge::consumer_index::ConsumerIndex;
    use ferrum_edge::plugins::StreamConnectionContext;
    use std::sync::Arc;

    let plugin = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 1, "percentage": 100.0 }
    }))
    .unwrap();

    let mut ctx = StreamConnectionContext {
        client_ip: "127.0.0.1".to_string(),
        direct_client_ip: "127.0.0.1".to_string(),
        proxy_id: "test-proxy".to_string(),
        proxy_name: None,
        listen_port: 9000,
        backend_scheme: BackendScheme::Tcp,
        consumer_index: Arc::new(ConsumerIndex::new(&[])),
        identified_consumer: None,
        authenticated_identity: None,
        auth_method: None,
        metadata: None,
        tls_client_cert_der: None,
        tls_client_cert_chain_der: None,
        sni_hostname: None,
        mesh_direction: None,
        node_waypoint_policy_scope: None,
        first_bytes: None,
        first_bytes_kind: None,
    };

    let start = std::time::Instant::now();
    let result = plugin.on_stream_connect(&mut ctx).await;
    let elapsed = start.elapsed();

    assert!(matches!(result, PluginResult::Continue));
    assert!(elapsed.as_millis() >= 1);

    let metadata = ctx.take_metadata();
    assert_eq!(metadata.get("fault_injected").unwrap(), "true");
    assert_eq!(metadata.get("fault_type").unwrap(), "delay");
}

// === GAP-3E: RTDS overlay-driven percentages ===

#[test]
fn test_runtime_overlay_scope_accepted() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0 },
        "runtime_overlay_scope": "checkout"
    }));
    assert!(plugin.is_ok(), "non-empty scope must be accepted");
}

#[test]
fn test_reject_empty_runtime_overlay_scope() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0 },
        "runtime_overlay_scope": "   "
    }))
    .err()
    .unwrap();
    assert!(err.contains("runtime_overlay_scope"));
}

#[test]
fn test_reject_non_string_runtime_overlay_scope() {
    let err = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0 },
        "runtime_overlay_scope": 42
    }))
    .err()
    .unwrap();
    assert!(err.contains("runtime_overlay_scope"));
}

// The four cases below share the process-global RTDS overlay ArcSwap, so
// running them as separate `#[tokio::test]` functions in parallel races
// each other's `reset_for_test()` calls. They are collapsed into one
// async block whose sub-steps run serially behind a local mutex — the
// behaviours under test (overlay zero, overlay full, missing scope,
// partial override) stay independent and each step still asserts its own
// expectation.
#[tokio::test]
async fn test_runtime_overlay_behaviours_are_observable_end_to_end() {
    use ferrum_edge::modes::mesh::config::{
        FractionalPercentDenominator, MeshRuntimeOverlay, RuntimeFractionalPercent, RuntimeValue,
    };
    use ferrum_edge::plugins::fault_injection::runtime_overlay;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    static GUARD: Mutex<()> = Mutex::const_new(());
    let _guard = GUARD.lock().await;

    // ── Case 1: overlay drops abort rate to ~0% ───────────────────────
    runtime_overlay::reset_for_test();
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 },
        "runtime_overlay_scope": "overlay_zero_abort"
    }))
    .unwrap();
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.overlay_zero_abort.abort_percent".to_string(),
        RuntimeValue::Number(0.001),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut continues = 0;
    for _ in 0..1000 {
        let mut ctx = make_ctx();
        if matches!(
            run_before_proxy(&plugin, &mut ctx).await,
            PluginResult::Continue
        ) {
            continues += 1;
        }
    }
    assert!(
        continues >= 990,
        "overlay should drop abort rate to ~0%, saw {continues}/1000 continues"
    );

    // ── Case 2: overlay pushes abort rate to 100% via FractionalPercent ─
    runtime_overlay::reset_for_test();
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 1.0 },
        "runtime_overlay_scope": "overlay_full_abort"
    }))
    .unwrap();
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.overlay_full_abort.abort_percent".to_string(),
        RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
            numerator: 100,
            denominator: FractionalPercentDenominator::Hundred,
        }),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut ctx = make_ctx();
    match run_before_proxy(&plugin, &mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 503),
        other => panic!("expected Reject when overlay forces 100% abort, got {other:?}"),
    }

    // ── Case 3: plugin without scope ignores overlay entries ──────────
    runtime_overlay::reset_for_test();
    // Seed an overlay with an unrelated scope.
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.someone_else.abort_percent".to_string(),
        RuntimeValue::Number(0.001),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        run_before_proxy(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));

    // ── Case 4: partial overlay (abort dropped, delay untouched) ──────
    runtime_overlay::reset_for_test();
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 },
        "delay": { "duration_ms": 1, "percentage": 100.0 },
        "runtime_overlay_scope": "partial_override"
    }))
    .unwrap();
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.partial_override.abort_percent".to_string(),
        RuntimeValue::Number(0.001),
    );
    runtime_overlay::apply_overlay(&MeshRuntimeOverlay { fields });
    let mut ctx = make_ctx();
    assert!(matches!(
        run_before_proxy(&plugin, &mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("fault_injected").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("fault_type").map(String::as_str),
        Some("delay")
    );

    runtime_overlay::reset_for_test();
}
