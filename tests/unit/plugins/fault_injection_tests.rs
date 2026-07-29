//! Tests for fault_injection plugin

use ferrum_edge::_test_support::{normalize_reject_response, set_request_http_flavor_for_test};
use ferrum_edge::HttpFlavor;
use ferrum_edge::plugins::fault_injection::FaultInjectionPlugin;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use http::StatusCode;
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

async fn run_before_proxy_with_content_type(
    plugin: &FaultInjectionPlugin,
    ctx: &mut RequestContext,
    content_type: &str,
) -> PluginResult {
    let mut headers = HashMap::from([("content-type".to_string(), content_type.to_string())]);
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
    assert!(p.defer_before_proxy_until_backend_path_resolved());
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
fn test_valid_null_unused_fault_side() {
    for config in [
        json!({
            "abort": null,
            "delay": {"duration_ms": 1, "percentage": 25.0}
        }),
        json!({
            "abort": {"status_code": 503, "percentage": 25.0},
            "delay": null
        }),
    ] {
        assert!(
            FaultInjectionPlugin::new(&config).is_ok(),
            "null must represent an unused fault side: {config}"
        );
    }
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
        "delay": { "duration_ms": 60_001_u64, "percentage": 50.0 }
    }))
    .err()
    .unwrap();
    assert!(err.contains("duration_ms must be <="));
}

#[test]
fn test_delay_cap_boundary_is_accepted() {
    assert!(
        FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 60_000_u64, "percentage": 50.0 }
        }))
        .is_ok()
    );
}

#[test]
fn test_positive_sub_bucket_percentage_is_accepted() {
    assert!(
        FaultInjectionPlugin::new(&json!({
            "abort": {
                "status_code": 503,
                "percentage": f64::from_bits(1)
            }
        }))
        .is_ok()
    );
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
        ferrum_edge::plugins::ALL_PROTOCOLS
    );
    assert!(plugin.requires_udp_datagram_hooks());
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
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Grpc);
    let result = run_before_proxy_with_content_type(
        &plugin,
        &mut ctx,
        "application/grpc+proto; charset=utf-8",
    )
    .await;

    match result {
        PluginResult::Reject { headers, .. } => {
            assert_eq!(headers.get("grpc-status").unwrap(), "2");
        }
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn test_abort_omits_grpc_status_for_plain_http_and_grpc_web() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "grpc_status": 14 }
    }))
    .unwrap();

    for content_type in [
        "text/plain",
        "application/grpc-web+proto",
        "application/grpcfoo",
    ] {
        let mut ctx = make_ctx();
        let result = run_before_proxy_with_content_type(&plugin, &mut ctx, content_type).await;
        match result {
            PluginResult::Reject { headers, .. } => {
                assert!(
                    !headers.contains_key("grpc-status"),
                    "{content_type} must not receive a native gRPC status header"
                );
            }
            _ => panic!("expected Reject"),
        }
    }

    let mut ctx = make_ctx();
    match run_before_proxy(&plugin, &mut ctx).await {
        PluginResult::Reject { headers, .. } => {
            assert!(!headers.contains_key("grpc-status"));
        }
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn test_abort_omits_grpc_status_after_grpc_web_translation() {
    let grpc_web = ferrum_edge::plugins::create_plugin("grpc_web", &json!({}))
        .unwrap()
        .unwrap();
    let fault = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "grpc_status": 14 }
    }))
    .unwrap();
    let mut ctx = make_ctx();
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::Plain);
    ctx.headers.insert(
        "content-type".to_string(),
        "application/grpc-web+proto".to_string(),
    );

    assert!(matches!(
        grpc_web.on_request_received(&mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.headers.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
    let mut headers = ctx.headers.clone();

    match fault.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert!(
                !headers.contains_key("grpc-status"),
                "translated gRPC-Web remains a plain-HTTP client response"
            );
        }
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn test_abort_omits_grpc_status_for_websocket_upgrade() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0, "grpc_status": 14 }
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::from([
        ("connection".to_string(), "upgrade".to_string()),
        ("upgrade".to_string(), "websocket".to_string()),
        ("content-type".to_string(), "application/grpc".to_string()),
    ]);
    set_request_http_flavor_for_test(&mut ctx, HttpFlavor::WebSocket);

    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject { headers, .. } => {
            assert!(!headers.contains_key("grpc-status"));
        }
        _ => panic!("expected Reject"),
    }
}

#[tokio::test]
async fn test_abort_uses_pre_plugin_flavor_after_content_type_mutation() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": {"status_code": 503, "percentage": 100.0, "grpc_status": 14}
    }))
    .unwrap();

    for (flavor, mutated_content_type, expected_grpc_status) in [
        (HttpFlavor::Grpc, "text/plain", true),
        (HttpFlavor::Grpc, "application/json", true),
        (HttpFlavor::Plain, "application/grpc", false),
        (HttpFlavor::WebSocket, "application/grpc", false),
    ] {
        let mut ctx = make_ctx();
        set_request_http_flavor_for_test(&mut ctx, flavor);
        let result =
            run_before_proxy_with_content_type(&plugin, &mut ctx, mutated_content_type).await;
        let PluginResult::Reject { headers, .. } = result else {
            panic!("expected Reject for {flavor:?}");
        };
        assert_eq!(
            headers.get("grpc-status").map(String::as_str),
            expected_grpc_status.then_some("14"),
            "fixed flavor {flavor:?} must win over mutated content-type {mutated_content_type}"
        );
    }
}

#[tokio::test]
async fn test_fault_rejection_shaping_matches_request_protocols() {
    let plugin = FaultInjectionPlugin::new(&json!({
        "abort": {
            "status_code": 503,
            "percentage": 100.0,
            "grpc_status": 14,
            "body": "fault"
        }
    }))
    .unwrap();

    for (protocol, content_type, is_native_grpc) in [
        ("HTTP/1.1", "text/plain", false),
        ("non-gRPC HTTP/2", "application/json", false),
        ("non-gRPC HTTP/3", "application/octet-stream", false),
        ("gRPC-Web", "application/grpc-web+proto", false),
        ("gRPC-like invalid type", "application/grpcfoo", false),
        ("native gRPC over HTTP/2", "application/grpc", true),
        ("native gRPC over HTTP/3", "application/grpc+proto", true),
    ] {
        let mut ctx = make_ctx();
        set_request_http_flavor_for_test(
            &mut ctx,
            if is_native_grpc {
                HttpFlavor::Grpc
            } else {
                HttpFlavor::Plain
            },
        );
        let PluginResult::Reject {
            status_code,
            body,
            headers,
        } = run_before_proxy_with_content_type(&plugin, &mut ctx, content_type).await
        else {
            panic!("{protocol} fault must reject");
        };
        let normalized = normalize_reject_response(
            StatusCode::from_u16(status_code).unwrap(),
            body.as_bytes(),
            &headers,
            is_native_grpc,
        );

        if is_native_grpc {
            assert_eq!(normalized.http_status, StatusCode::OK, "{protocol}");
            assert!(normalized.body.is_empty(), "{protocol}");
            assert_eq!(normalized.grpc_status, Some(14), "{protocol}");
            assert_eq!(
                normalized.headers.get("grpc-status").map(String::as_str),
                Some("14"),
                "{protocol}"
            );
        } else {
            assert_eq!(normalized.http_status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(&normalized.body[..], b"fault", "{protocol}");
            assert_eq!(normalized.grpc_status, None, "{protocol}");
            assert!(
                !normalized.headers.contains_key("grpc-status"),
                "{protocol}"
            );
        }
    }

    let mut ctx = make_ctx();
    let mut websocket_headers = HashMap::from([
        ("connection".to_string(), "upgrade".to_string()),
        ("upgrade".to_string(), "websocket".to_string()),
    ]);
    let PluginResult::Reject {
        status_code,
        body,
        headers,
    } = plugin.before_proxy(&mut ctx, &mut websocket_headers).await
    else {
        panic!("WebSocket handshake fault must reject");
    };
    let normalized = normalize_reject_response(
        StatusCode::from_u16(status_code).unwrap(),
        body.as_bytes(),
        &headers,
        false,
    );
    assert_eq!(normalized.http_status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!normalized.headers.contains_key("grpc-status"));
}

#[tokio::test]
async fn test_later_fault_instance_is_not_suppressed_by_earlier_delay() {
    let delay = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 1, "percentage": 100.0 }
    }))
    .unwrap();
    let abort = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();
    let mut ctx = make_ctx();

    assert!(matches!(
        run_before_proxy(&delay, &mut ctx).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        run_before_proxy(&abort, &mut ctx).await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[tokio::test]
async fn test_later_delay_instance_is_not_suppressed_by_earlier_abort_marker() {
    let abort = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();
    let delay = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 1, "percentage": 100.0 }
    }))
    .unwrap();
    let mut ctx = make_ctx();

    assert!(matches!(
        run_before_proxy(&abort, &mut ctx).await,
        PluginResult::Reject { .. }
    ));
    // Directly invoke the next instance to verify the generic observability
    // marker is not interpreted as a same-type suppression marker. A real
    // proxy stops its hook chain at the abort result above.
    assert!(matches!(
        run_before_proxy(&delay, &mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("fault_type").map(String::as_str),
        Some("delay")
    );
}

#[tokio::test]
async fn test_zero_overlay_disables_one_instance_without_affecting_sibling_config() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::fault_injection::runtime_overlay::{
        FaultOverlayMaterialization, materialize_config,
    };

    let mut disabled_config = json!({
        "delay": { "duration_ms": 1, "percentage": 100.0 },
        "runtime_overlay_scope": "miss"
    });
    assert_eq!(
        materialize_config(
            &mut disabled_config,
            &MeshRuntimeOverlay {
                fields: HashMap::from([(
                    "ferrum.fault_injection.miss.delay_percent".to_string(),
                    RuntimeValue::Number(0.0),
                )]),
            },
        ),
        FaultOverlayMaterialization::Disabled
    );
    assert!(disabled_config.get("delay").is_none());

    let hit = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        run_before_proxy(&hit, &mut ctx).await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[test]
fn test_zero_overlay_treats_null_fault_sides_as_absent() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::fault_injection::runtime_overlay::{
        FaultOverlayMaterialization, materialize_config,
    };

    for (mut config, key, removed_side) in [
        (
            json!({
                "abort": null,
                "delay": {"duration_ms": 10, "percentage": 25.0},
                "runtime_overlay_scope": "checkout"
            }),
            "ferrum.fault_injection.checkout.delay_percent",
            "delay",
        ),
        (
            json!({
                "abort": {"status_code": 503, "percentage": 25.0},
                "delay": null,
                "runtime_overlay_scope": "checkout"
            }),
            "ferrum.fault_injection.checkout.abort_percent",
            "abort",
        ),
    ] {
        assert_eq!(
            materialize_config(
                &mut config,
                &MeshRuntimeOverlay {
                    fields: HashMap::from([(key.to_string(), RuntimeValue::Number(0.0))]),
                },
            ),
            FaultOverlayMaterialization::Disabled,
            "zeroing the only object side must disable despite a null sibling: {config}"
        );
        assert!(config.get(removed_side).is_none());
    }

    let mut both_objects = json!({
        "abort": {"status_code": 503, "percentage": 25.0},
        "delay": {"duration_ms": 10, "percentage": 25.0},
        "runtime_overlay_scope": "checkout"
    });
    assert_eq!(
        materialize_config(
            &mut both_objects,
            &MeshRuntimeOverlay {
                fields: HashMap::from([(
                    "ferrum.fault_injection.checkout.delay_percent".to_string(),
                    RuntimeValue::Number(0.0),
                )]),
            },
        ),
        FaultOverlayMaterialization::Changed,
        "an object sibling keeps the generation enabled"
    );
    assert!(
        both_objects
            .get("abort")
            .is_some_and(serde_json::Value::is_object)
    );
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
    for invalid_scope in [json!(42), json!(true), json!({})] {
        let err = FaultInjectionPlugin::new(&json!({
            "abort": { "status_code": 503, "percentage": 50.0 },
            "runtime_overlay_scope": invalid_scope
        }))
        .err()
        .unwrap();
        assert!(err.contains("runtime_overlay_scope"));
    }
}

#[test]
fn test_null_runtime_overlay_scope_is_equivalent_to_omission() {
    let with_null = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0 },
        "runtime_overlay_scope": null
    }));
    let omitted = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 50.0 }
    }));
    assert!(with_null.is_ok());
    assert!(omitted.is_ok());
}

#[tokio::test]
async fn test_runtime_overlay_behaviours_are_observable_end_to_end() {
    use ferrum_edge::modes::mesh::config::{
        FractionalPercentDenominator, MeshRuntimeOverlay, RuntimeFractionalPercent, RuntimeValue,
    };
    use ferrum_edge::plugins::fault_injection::runtime_overlay::{
        FaultOverlayMaterialization, materialize_config,
    };
    use std::collections::HashMap;

    // ── Case 1: overlay drops the only abort side to 0% ───────────────
    let mut config = json!({
        "abort": { "status_code": 503, "percentage": 100.0 },
        "runtime_overlay_scope": "overlay_zero_abort"
    });
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.overlay_zero_abort.abort_percent".to_string(),
        RuntimeValue::Number(0.0),
    );
    assert_eq!(
        materialize_config(&mut config, &MeshRuntimeOverlay { fields }),
        FaultOverlayMaterialization::Disabled
    );
    assert!(config.get("abort").is_none());

    // ── Case 2: overlay pushes abort rate to 100% via FractionalPercent ─
    let mut config = json!({
        "abort": { "status_code": 503, "percentage": 1.0 },
        "runtime_overlay_scope": "overlay_full_abort"
    });
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.overlay_full_abort.abort_percent".to_string(),
        RuntimeValue::FractionalPercent(RuntimeFractionalPercent {
            numerator: 100,
            denominator: FractionalPercentDenominator::Hundred,
        }),
    );
    assert_eq!(
        materialize_config(&mut config, &MeshRuntimeOverlay { fields }),
        FaultOverlayMaterialization::Changed
    );
    let plugin = FaultInjectionPlugin::new(&config).unwrap();
    let mut ctx = make_ctx();
    match run_before_proxy(&plugin, &mut ctx).await {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 503),
        _ => panic!("expected Reject from 100% RTDS override"),
    }

    // ── Case 3: plugin without scope ignores overlay entries ──────────
    let mut config = json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    });
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.someone_else.abort_percent".to_string(),
        RuntimeValue::Number(0.0),
    );
    assert_eq!(
        materialize_config(&mut config, &MeshRuntimeOverlay { fields }),
        FaultOverlayMaterialization::Unchanged
    );
    let plugin = FaultInjectionPlugin::new(&config).unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        run_before_proxy(&plugin, &mut ctx).await,
        PluginResult::Reject { .. }
    ));

    // ── Case 4: partial overlay disables abort, leaves delay static ───
    let mut config = json!({
        "abort": { "status_code": 503, "percentage": 100.0 },
        "delay": { "duration_ms": 1, "percentage": 100.0 },
        "runtime_overlay_scope": "partial_override"
    });
    let mut fields = HashMap::new();
    fields.insert(
        "ferrum.fault_injection.partial_override.abort_percent".to_string(),
        RuntimeValue::Number(0.0),
    );
    assert_eq!(
        materialize_config(&mut config, &MeshRuntimeOverlay { fields }),
        FaultOverlayMaterialization::Changed
    );
    let plugin = FaultInjectionPlugin::new(&config).unwrap();
    let mut ctx = make_ctx();
    assert!(matches!(
        run_before_proxy(&plugin, &mut ctx).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get("fault_type").map(String::as_str),
        Some("delay")
    );
}

#[test]
fn test_runtime_overlay_materializations_are_generation_local() {
    use ferrum_edge::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};
    use ferrum_edge::plugins::fault_injection::runtime_overlay::{
        FaultOverlayMaterialization, materialize_config,
    };

    let static_config = json!({
        "abort": { "status_code": 503, "percentage": 50.0 },
        "runtime_overlay_scope": "generation"
    });
    let mut old_config = static_config.clone();
    let old_result = materialize_config(
        &mut old_config,
        &MeshRuntimeOverlay {
            fields: HashMap::from([(
                "ferrum.fault_injection.generation.abort_percent".to_string(),
                RuntimeValue::Number(0.0),
            )]),
        },
    );
    let mut new_config = static_config.clone();
    let new_result = materialize_config(
        &mut new_config,
        &MeshRuntimeOverlay {
            fields: HashMap::from([(
                "ferrum.fault_injection.generation.abort_percent".to_string(),
                RuntimeValue::Number(100.0),
            )]),
        },
    );

    assert_eq!(old_result, FaultOverlayMaterialization::Disabled);
    assert_eq!(new_result, FaultOverlayMaterialization::Changed);
    assert!(old_config.get("abort").is_none());
    assert_eq!(new_config["abort"]["percentage"], json!(100.0));
    assert_eq!(static_config["abort"]["percentage"], json!(50.0));
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

    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "test-proxy".to_string(),
        None,
        9000,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );

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

    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "test-proxy".to_string(),
        None,
        9000,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );

    let start = std::time::Instant::now();
    let result = plugin.on_stream_connect(&mut ctx).await;
    let elapsed = start.elapsed();

    assert!(matches!(result, PluginResult::Continue));
    assert!(elapsed.as_millis() >= 1);

    let metadata = ctx.take_metadata();
    assert_eq!(metadata.get("fault_injected").unwrap(), "true");
    assert_eq!(metadata.get("fault_type").unwrap(), "delay");
}

#[tokio::test]
async fn test_later_stream_fault_instance_is_not_suppressed_by_earlier_delay() {
    use ferrum_edge::config::types::BackendScheme;
    use ferrum_edge::consumer_index::ConsumerIndex;
    use ferrum_edge::plugins::StreamConnectionContext;
    use std::sync::Arc;

    let delay = FaultInjectionPlugin::new(&json!({
        "delay": { "duration_ms": 1, "percentage": 100.0 }
    }))
    .unwrap();
    let abort = FaultInjectionPlugin::new(&json!({
        "abort": { "status_code": 503, "percentage": 100.0 }
    }))
    .unwrap();
    let mut ctx = StreamConnectionContext::new(
        "127.0.0.1".to_string(),
        "127.0.0.1".to_string(),
        "test-proxy".to_string(),
        None,
        9000,
        BackendScheme::Tcp,
        Arc::new(ConsumerIndex::new(&[])),
    );

    assert!(matches!(
        delay.on_stream_connect(&mut ctx).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        abort.on_stream_connect(&mut ctx).await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[test]
fn virtual_service_fault_documentation_names_route_local_translation() {
    let configuration = include_str!("../../../docs/configuration.md");
    let mesh = include_str!("../../../docs/mesh.md");
    assert!(configuration.contains("mesh_route_dispatch"));
    assert!(mesh.contains("Per-route `fault` rides on each emitted `mesh_route_dispatch` rule"));
    assert!(mesh.contains("Per-rule fault percentages are not RTDS-tunable"));
    assert!(!configuration.contains("fault` injection maps to proxy-scoped `fault_injection`"));
}

// ── Peer-departure cancellation (GHSA-484w-rxg2-7jg5) ────────────────
//
// These exercise the `RequestContext::peer_connection` boundary the HTTP/3
// frontend stamps. They deliberately avoid the process-global shutdown token:
// cancelling a one-shot global from a test would disarm every other
// fault-delay assertion in this binary.

mod peer_departure {
    use super::*;
    use ferrum_edge::plugins::{PeerConnectionSignal, PeerConnectionWatch};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    /// Test double for a frontend transport watch. Mirrors the HTTP/3 QUIC
    /// connection-close watch: observable without touching request bytes.
    struct TestPeerWatch {
        gone: CancellationToken,
    }

    impl PeerConnectionWatch for TestPeerWatch {
        fn closed(&self) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            let gone = self.gone.clone();
            Box::pin(async move { gone.cancelled().await })
        }

        fn is_closed(&self) -> bool {
            self.gone.is_cancelled()
        }
    }

    fn ctx_with_peer(gone: &CancellationToken) -> RequestContext {
        let mut ctx = make_ctx();
        ctx.peer_connection = Some(PeerConnectionSignal::new(Arc::new(TestPeerWatch {
            gone: gone.clone(),
        })));
        ctx
    }

    /// The advisory's core amplifier: a client that reaches a long delay and
    /// immediately disappears must not keep the request parked.
    #[tokio::test]
    async fn peer_departure_during_a_long_delay_abandons_the_request() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 60_000_u64, "percentage": 100.0 }
        }))
        .unwrap();

        let gone = CancellationToken::new();
        let mut ctx = ctx_with_peer(&gone);

        let closer = gone.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            closer.cancel();
        });

        let start = std::time::Instant::now();
        let result = run_before_proxy(&plugin, &mut ctx).await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "the delay must end when the peer leaves, took {elapsed:?}"
        );
        match result {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 499, "client-closed-request convention");
                assert!(body.is_empty(), "no body is owed to a departed client");
            }
            other => panic!("expected a 499 reject, got {other:?}"),
        }
        assert_eq!(
            ctx.metadata.get("fault_delay_outcome").unwrap(),
            "peer_gone"
        );
        assert_eq!(ctx.metadata.get("fault_type").unwrap(), "delay");
        assert_eq!(ctx.metadata.get("fault_delay_ms").unwrap(), "60000");
    }

    /// An already-dead transport must not even consume a budget slot.
    #[tokio::test]
    async fn an_already_closed_peer_short_circuits_before_the_timer() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 60_000_u64, "percentage": 100.0 }
        }))
        .unwrap();

        let gone = CancellationToken::new();
        gone.cancel();
        let mut ctx = ctx_with_peer(&gone);

        let start = std::time::Instant::now();
        let result = run_before_proxy(&plugin, &mut ctx).await;
        let elapsed = start.elapsed();

        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
        assert!(matches!(
            result,
            PluginResult::Reject {
                status_code: 499,
                ..
            }
        ));
        assert_eq!(
            ctx.metadata.get("fault_delay_outcome").unwrap(),
            "peer_gone"
        );
    }

    /// A departed peer preempts a co-triggered abort: the abort's status is a
    /// response nobody can read, so the request is abandoned instead.
    #[tokio::test]
    async fn peer_departure_preempts_a_co_triggered_abort() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "abort": { "status_code": 503, "percentage": 100.0, "body": "injected" },
            "delay": { "duration_ms": 60_000_u64, "percentage": 100.0 }
        }))
        .unwrap();

        let gone = CancellationToken::new();
        gone.cancel();
        let mut ctx = ctx_with_peer(&gone);

        match run_before_proxy(&plugin, &mut ctx).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 499);
                assert!(body.is_empty());
            }
            other => panic!("expected a 499 reject, got {other:?}"),
        }
        assert!(
            !ctx.metadata.contains_key("fault_abort_status"),
            "the abort must not also fire for a departed client"
        );
    }

    /// A live peer must be entirely unaffected — no early exit, no new
    /// metadata, and the ordinary delay/abort semantics preserved.
    #[tokio::test]
    async fn a_live_peer_still_gets_the_configured_delay() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 1, "percentage": 100.0 }
        }))
        .unwrap();

        let gone = CancellationToken::new();
        let mut ctx = ctx_with_peer(&gone);

        let start = std::time::Instant::now();
        let result = run_before_proxy(&plugin, &mut ctx).await;

        assert!(matches!(result, PluginResult::Continue));
        assert!(start.elapsed().as_millis() >= 1);
        assert_eq!(ctx.metadata.get("fault_type").unwrap(), "delay");
        assert_eq!(ctx.metadata.get("fault_delay_ms").unwrap(), "1");
        assert!(
            !ctx.metadata.contains_key("fault_delay_outcome"),
            "a completed delay must not add an outcome field"
        );
    }

    /// A percentage miss must not consult the peer watch or park anything,
    /// no matter how many times the same connection re-requests.
    #[tokio::test]
    async fn repeated_streams_that_miss_the_roll_never_park() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 60_000_u64, "percentage": 1e-300 }
        }))
        .unwrap();

        let gone = CancellationToken::new();
        let start = std::time::Instant::now();
        for _ in 0..64 {
            let mut ctx = ctx_with_peer(&gone);
            let result = run_before_proxy(&plugin, &mut ctx).await;
            assert!(matches!(result, PluginResult::Continue));
            assert!(!ctx.metadata.contains_key("fault_delay_ms"));
            assert!(!ctx.metadata.contains_key("fault_delay_outcome"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "misses must not wait"
        );
    }

    /// Requests without a frontend watch (HTTP/1.1, HTTP/2) keep their
    /// pre-existing behavior exactly.
    #[tokio::test]
    async fn a_context_without_a_peer_watch_is_unchanged() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 1, "percentage": 100.0 }
        }))
        .unwrap();

        let mut ctx = make_ctx();
        assert!(ctx.peer_connection.is_none());

        let result = run_before_proxy(&plugin, &mut ctx).await;

        assert!(matches!(result, PluginResult::Continue));
        assert_eq!(ctx.metadata.get("fault_type").unwrap(), "delay");
        assert!(!ctx.metadata.contains_key("fault_delay_outcome"));
    }
}

// === UDP / DTLS datagram path ===

mod udp_datagram_faults {
    use super::*;
    use ferrum_edge::plugins::{
        StreamBytesKind, UdpDatagramContext, UdpDatagramDirection, UdpDatagramVerdict,
        UdpMetadataSink,
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn datagram_ctx<'a>(
        direction: UdpDatagramDirection,
        payload: &'a [u8],
        sink: Option<UdpMetadataSink<'a>>,
    ) -> UdpDatagramContext<'a> {
        UdpDatagramContext {
            client_ip: Arc::from("127.0.0.1"),
            proxy_id: Arc::from("udp-proxy"),
            proxy_name: Some(Arc::from("udp")),
            listen_port: 9000,
            datagram_size: payload.len(),
            direction,
            payload,
            payload_kind: StreamBytesKind::PlaintextWire,
            metadata_sink: sink,
        }
    }

    #[tokio::test]
    async fn abort_drops_client_to_backend_datagram_and_records_metadata() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "abort": { "status_code": 503, "percentage": 100.0 }
        }))
        .unwrap();

        let metadata = Mutex::new(HashMap::new());
        let ctx = datagram_ctx(
            UdpDatagramDirection::ClientToBackend,
            b"ping",
            Some(UdpMetadataSink::new(&metadata)),
        );
        let verdict = plugin.on_udp_datagram(&ctx).await;
        assert_eq!(verdict, UdpDatagramVerdict::Drop);

        let map = metadata.lock().unwrap();
        assert_eq!(map.get("fault_injected").unwrap(), "true");
        assert_eq!(map.get("fault_type").unwrap(), "abort");
        assert_eq!(map.get("fault_abort_status").unwrap(), "503");
    }

    #[tokio::test]
    async fn abort_does_not_fault_backend_to_client_datagrams() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "abort": { "status_code": 503, "percentage": 100.0 }
        }))
        .unwrap();

        let ctx = datagram_ctx(UdpDatagramDirection::BackendToClient, b"pong", None);
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
    }

    #[tokio::test]
    async fn delay_then_abort_delays_before_drop() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "abort": { "status_code": 500, "percentage": 100.0 },
            "delay": { "duration_ms": 1, "percentage": 100.0 }
        }))
        .unwrap();

        let metadata = Mutex::new(HashMap::new());
        let ctx = datagram_ctx(
            UdpDatagramDirection::ClientToBackend,
            b"ping",
            Some(UdpMetadataSink::new(&metadata)),
        );
        let start = std::time::Instant::now();
        let verdict = plugin.on_udp_datagram(&ctx).await;
        assert!(start.elapsed() >= std::time::Duration::from_millis(1));
        assert_eq!(verdict, UdpDatagramVerdict::Drop);

        let map = metadata.lock().unwrap();
        assert_eq!(map.get("fault_type").unwrap(), "delay_and_abort");
        assert_eq!(map.get("fault_delay_ms").unwrap(), "1");
    }

    #[tokio::test]
    async fn delay_only_forwards_after_wait() {
        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 1, "percentage": 100.0 }
        }))
        .unwrap();

        let metadata = Mutex::new(HashMap::new());
        let ctx = datagram_ctx(
            UdpDatagramDirection::ClientToBackend,
            b"ping",
            Some(UdpMetadataSink::new(&metadata)),
        );
        assert_eq!(
            plugin.on_udp_datagram(&ctx).await,
            UdpDatagramVerdict::Forward
        );
        let map = metadata.lock().unwrap();
        assert_eq!(map.get("fault_type").unwrap(), "delay");
        assert_eq!(map.get("fault_delay_ms").unwrap(), "1");
    }

    #[tokio::test]
    async fn stream_connect_abort_rejects_udp_session_admission() {
        use ferrum_edge::config::types::BackendScheme;
        use ferrum_edge::consumer_index::ConsumerIndex;
        use ferrum_edge::plugins::StreamConnectionContext;

        let plugin = FaultInjectionPlugin::new(&json!({
            "abort": { "status_code": 503, "percentage": 100.0 }
        }))
        .unwrap();

        let mut ctx = StreamConnectionContext::new(
            "127.0.0.1".to_string(),
            "127.0.0.1".to_string(),
            "udp-proxy".to_string(),
            Some("udp".to_string()),
            9000,
            BackendScheme::Udp,
            Arc::new(ConsumerIndex::new(&[])),
        );
        match plugin.on_stream_connect(&mut ctx).await {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 503),
            other => panic!("expected Reject, got {other:?}"),
        }
        let metadata = ctx.take_metadata();
        assert_eq!(metadata.get("fault_type").unwrap(), "abort");
    }

    #[tokio::test]
    async fn stream_connect_delay_is_skipped_for_udp_so_datagram_hook_owns_latency() {
        use ferrum_edge::config::types::BackendScheme;
        use ferrum_edge::consumer_index::ConsumerIndex;
        use ferrum_edge::plugins::StreamConnectionContext;

        let plugin = FaultInjectionPlugin::new(&json!({
            "delay": { "duration_ms": 5_000, "percentage": 100.0 }
        }))
        .unwrap();

        let mut ctx = StreamConnectionContext::new(
            "127.0.0.1".to_string(),
            "127.0.0.1".to_string(),
            "udp-proxy".to_string(),
            None,
            9000,
            BackendScheme::Udp,
            Arc::new(ConsumerIndex::new(&[])),
        );
        let start = std::time::Instant::now();
        assert!(matches!(
            plugin.on_stream_connect(&mut ctx).await,
            PluginResult::Continue
        ));
        assert!(
            start.elapsed() < std::time::Duration::from_millis(500),
            "UDP stream connect must not park on delay"
        );
    }
}
