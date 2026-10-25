//! Tests for ws_message_size_limiting plugin configuration and parser policy.

use ferrum_edge::_test_support::{
    effective_ws_size_limits_for_test, ws_permessage_deflate_fault_close_for_test,
    ws_plugin_capacity_close_for_test,
};
use ferrum_edge::plugins::prometheus_metrics::MetricsRegistry;
use ferrum_edge::plugins::ws_message_size_limiting::WsMessageSizeLimiting;
use ferrum_edge::plugins::{
    Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketFrameDirection, priority,
};
use ferrum_edge::proxy::ws_permessage_deflate::PermessageDeflateFault;
use serde_json::json;
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::error::CapacityError;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

const DIRECTIONS: [WebSocketFrameDirection; 2] = [
    WebSocketFrameDirection::ClientToBackend,
    WebSocketFrameDirection::BackendToClient,
];

fn limiter(config: serde_json::Value) -> Arc<dyn Plugin> {
    Arc::new(WsMessageSizeLimiting::new(&config).expect("valid limiter config"))
}

#[test]
fn test_creation_defaults_to_four_frame_reassembly_window() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
    assert_eq!(plugin.name(), "ws_message_size_limiting");
    assert_eq!(plugin.priority(), priority::WS_MESSAGE_SIZE_LIMITING);
    assert!(!plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());

    let limits = plugin.websocket_size_limits().expect("parser limits");
    for direction in DIRECTIONS {
        let limits = limits.for_direction(direction);
        assert_eq!(limits.max_frame_bytes, 1024);
        assert_eq!(limits.max_message_bytes, 4096);
        assert_eq!(limits.close_reason.as_ref(), "Message too large");
    }
}

#[test]
fn test_explicit_reassembled_message_limit() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "max_message_bytes": 8192,
        "close_reason": "proxy payload ceiling"
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    for direction in DIRECTIONS {
        let limits = limits.for_direction(direction);
        assert_eq!(limits.max_frame_bytes, 1024);
        assert_eq!(limits.max_message_bytes, 8192);
        assert_eq!(limits.close_reason.as_ref(), "proxy payload ceiling");
    }
}

#[test]
fn test_supported_protocols_and_frame_parser_opt_in() {
    let plugin = WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, WS_ONLY_PROTOCOLS);
    assert!(protocols.contains(&ProxyProtocol::WebSocket));
    assert!(!protocols.contains(&ProxyProtocol::Http));
    assert!(!protocols.contains(&ProxyProtocol::Grpc));
    assert!(!protocols.contains(&ProxyProtocol::Tcp));
    assert!(!protocols.contains(&ProxyProtocol::Udp));
    assert!(
        !plugin.requires_ws_frame_hooks(),
        "parser policy must not require the post-reassembly message hook"
    );
    assert!(plugin.requires_websocket_framing());
}

#[test]
fn test_parser_only_plugin_is_excluded_from_message_hook_list() {
    let plugin: Arc<dyn Plugin> =
        Arc::new(WsMessageSizeLimiting::new(&json!({"max_frame_bytes": 1024})).unwrap());
    let upgrade_ctx = ferrum_edge::plugins::RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        "/ws".to_string(),
    );
    let (framing_plugins, frame_plugins) =
        ferrum_edge::_test_support::websocket_relay_plugin_names_for_test(
            &[plugin],
            true,
            &upgrade_ctx,
        );
    assert_eq!(
        framing_plugins,
        vec!["ws_message_size_limiting".to_string()]
    );
    assert!(
        frame_plugins.is_empty(),
        "parser-only policy must not enter the per-message hook loop"
    );
}

#[test]
fn test_invalid_configuration_is_rejected() {
    for config in [
        json!("bad"),
        json!({}),
        json!({"max_frame_bytes": 0}),
        json!({"max_frame_bytes": 1024, "max_message_bytes": 0}),
        json!({"max_frame_bytes": 1024, "max_message_bytes": 512}),
        json!({"max_frame_bytes": 1024, "close_reason": 123}),
    ] {
        assert!(
            WsMessageSizeLimiting::new(&config).is_err(),
            "configuration should fail: {config}"
        );
    }
}

#[test]
fn test_unknown_config_key_max_frame_bytez_is_rejected() {
    let err = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "max_frame_bytez": 2048
    }))
    .err()
    .expect("typo max_frame_bytez must be rejected");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(err.contains("max_frame_bytez"), "{err}");
    assert!(err.contains("did you mean `max_frame_bytes`?"), "{err}");
}

#[test]
fn test_close_reason_is_truncated_on_utf8_boundary() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 5,
        "close_reason": "🙂".repeat(40)
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    for direction in DIRECTIONS {
        let reason = &limits.for_direction(direction).close_reason;
        assert!(reason.len() <= 123);
        assert!(std::str::from_utf8(reason.as_bytes()).is_ok());
    }

    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 5,
        "backend_to_client": {"close_reason": "é".repeat(80)}
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    let reason = &limits.backend_to_client.close_reason;
    assert!(reason.len() <= 123, "override reason is bounded too");
    assert!(reason.starts_with('é'));
    assert_eq!(
        limits.client_to_backend.close_reason.as_ref(),
        "Message too large"
    );
}

#[tokio::test]
async fn test_reassembled_message_is_not_mistaken_for_one_frame() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 64,
        "max_message_bytes": 256
    }))
    .unwrap();
    let reassembled = Message::Binary(vec![0; 128].into());

    // `on_ws_frame` receives tungstenite messages after continuation
    // reassembly. Actual frame enforcement belongs to the parser-level policy,
    // so a valid 2x64-byte fragmented message must not be rejected here.
    assert!(
        plugin
            .on_ws_frame(
                "test-proxy",
                1,
                WebSocketFrameDirection::ClientToBackend,
                &reassembled,
            )
            .await
            .is_none()
    );
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    for (config, field, reason) in [
        (
            json!({"max_frame_bytes": false}),
            "`max_frame_bytes`",
            "must be greater than zero",
        ),
        (
            json!({"max_frame_bytes": 918273641, "max_message_bytes": 1}),
            "`max_message_bytes`",
            "must be greater than or equal",
        ),
    ] {
        let error =
            ferrum_edge::plugins::validate_plugin_config("ws_message_size_limiting", &config)
                .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{rendered}");
        assert!(rendered.contains(reason), "{rendered}");
        for withheld in ["UNREGISTERED_TRAFFIC_TOKEN", "918273641", "true", "false"] {
            assert!(!rendered.contains(withheld), "{withheld}: {rendered}");
        }
    }
}

// ── Directional overrides (client_to_backend / backend_to_client) ────────

#[test]
fn directional_overrides_resolve_each_direction_independently() {
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 4096,
        "max_message_bytes": 16384,
        "close_reason": "client payload limit",
        "backend_to_client": {
            "max_frame_bytes": 65536,
            "max_message_bytes": 262144,
            "close_reason": "backend payload limit"
        }
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    assert_eq!(limits.client_to_backend.max_frame_bytes, 4096);
    assert_eq!(limits.client_to_backend.max_message_bytes, 16384);
    assert_eq!(
        limits.client_to_backend.close_reason.as_ref(),
        "client payload limit"
    );
    assert_eq!(limits.backend_to_client.max_frame_bytes, 65536);
    assert_eq!(limits.backend_to_client.max_message_bytes, 262144);
    assert_eq!(
        limits.backend_to_client.close_reason.as_ref(),
        "backend payload limit"
    );
}

#[test]
fn directional_override_inherits_omitted_fields_from_top_level() {
    // No message ceiling anywhere: each direction derives 4x its own frame.
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "close_reason": "shared reason",
        "backend_to_client": {"max_frame_bytes": 8192}
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    assert_eq!(limits.client_to_backend.max_frame_bytes, 1024);
    assert_eq!(limits.client_to_backend.max_message_bytes, 4096);
    assert_eq!(limits.backend_to_client.max_frame_bytes, 8192);
    assert_eq!(limits.backend_to_client.max_message_bytes, 32768);
    assert_eq!(
        limits.backend_to_client.close_reason.as_ref(),
        "shared reason"
    );

    // An explicit top-level message ceiling is inherited verbatim.
    let plugin = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "max_message_bytes": 65536,
        "client_to_backend": {"max_frame_bytes": 512, "close_reason": "client cap"}
    }))
    .unwrap();
    let limits = plugin.websocket_size_limits().expect("parser limits");
    assert_eq!(limits.client_to_backend.max_frame_bytes, 512);
    assert_eq!(limits.client_to_backend.max_message_bytes, 65536);
    assert_eq!(limits.client_to_backend.close_reason.as_ref(), "client cap");
    assert_eq!(limits.backend_to_client.max_frame_bytes, 1024);
    assert_eq!(limits.backend_to_client.max_message_bytes, 65536);
    assert_eq!(
        limits.backend_to_client.close_reason.as_ref(),
        "Message too large"
    );
}

#[test]
fn invalid_directional_overrides_are_rejected() {
    for config in [
        // The top-level frame ceiling stays required as the shared default.
        json!({"backend_to_client": {"max_frame_bytes": 1024}}),
        json!({"max_frame_bytes": 1024, "client_to_backend": "bad"}),
        json!({"max_frame_bytes": 1024, "client_to_backend": null}),
        json!({"max_frame_bytes": 1024, "backend_to_client": {"max_frame_bytes": 0}}),
        json!({"max_frame_bytes": 1024, "backend_to_client": {"max_message_bytes": 0}}),
        json!({"max_frame_bytes": 1024, "backend_to_client": {"max_message_bytes": 512}}),
        json!({"max_frame_bytes": 1024, "client_to_backend": {"close_reason": 5}}),
        // An inherited explicit message ceiling below a raised frame ceiling.
        json!({
            "max_frame_bytes": 1024,
            "max_message_bytes": 2048,
            "backend_to_client": {"max_frame_bytes": 4096}
        }),
    ] {
        assert!(
            WsMessageSizeLimiting::new(&config).is_err(),
            "configuration should fail: {config}"
        );
    }
}

#[test]
fn directional_override_diagnostics_name_the_direction() {
    let err = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "max_message_bytes": 2048,
        "backend_to_client": {"max_frame_bytes": 4096}
    }))
    .err()
    .expect("inherited message ceiling below the override frame must fail");
    assert!(err.contains("`backend_to_client`"), "{err}");
    assert!(err.contains("`max_message_bytes`"), "{err}");

    let err = WsMessageSizeLimiting::new(&json!({
        "max_frame_bytes": 1024,
        "client_to_backend": {"max_frame_bytez": 2048}
    }))
    .err()
    .expect("typo inside an override must be rejected");
    assert!(err.contains("unknown configuration key"), "{err}");
    assert!(
        err.contains("config.client_to_backend.max_frame_bytez"),
        "{err}"
    );
    assert!(err.contains("did you mean `max_frame_bytes`?"), "{err}");
}

#[test]
fn relay_combines_limits_per_direction() {
    let plugins = [
        limiter(json!({
            "max_frame_bytes": 4096,
            "max_message_bytes": 16384,
            "backend_to_client": {"max_frame_bytes": 65536, "max_message_bytes": 262144}
        })),
        limiter(json!({
            "max_frame_bytes": 8192,
            "backend_to_client": {"max_frame_bytes": 32768}
        })),
    ];
    // Strictest wins per direction and per category, independently.
    assert_eq!(
        effective_ws_size_limits_for_test(
            1 << 20,
            &plugins,
            WebSocketFrameDirection::ClientToBackend
        ),
        (4096, 16384)
    );
    assert_eq!(
        effective_ws_size_limits_for_test(
            1 << 20,
            &plugins,
            WebSocketFrameDirection::BackendToClient
        ),
        (32768, 131072)
    );
    // The global frame ceiling still bounds both directions.
    assert_eq!(
        effective_ws_size_limits_for_test(
            16384,
            &plugins,
            WebSocketFrameDirection::BackendToClient
        ),
        (16384, 65536)
    );
}

#[test]
fn relay_attributes_capacity_errors_to_the_directional_rule() {
    let plugins = [limiter(json!({
        "max_frame_bytes": 4096,
        "close_reason": "client payload limit",
        "backend_to_client": {
            "max_frame_bytes": 65536,
            "close_reason": "backend payload limit"
        }
    }))];
    let client_frame = WsError::Capacity(CapacityError::FrameTooLong {
        size: 4097,
        max_size: 4096,
    });
    let close = ws_plugin_capacity_close_for_test(
        1 << 20,
        &plugins,
        WebSocketFrameDirection::ClientToBackend,
        &client_frame,
    )
    .expect("client frame over the client ceiling is plugin policy");
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(close.reason.as_str(), "client payload limit");
    assert!(
        ws_plugin_capacity_close_for_test(
            1 << 20,
            &plugins,
            WebSocketFrameDirection::BackendToClient,
            &client_frame,
        )
        .is_none(),
        "the backend framer's ceiling is 65536, so a 4096-byte rule cannot bind there"
    );

    let backend_frame = WsError::Capacity(CapacityError::FrameTooLong {
        size: 65537,
        max_size: 65536,
    });
    let close = ws_plugin_capacity_close_for_test(
        1 << 20,
        &plugins,
        WebSocketFrameDirection::BackendToClient,
        &backend_frame,
    )
    .expect("backend frame over the backend ceiling is plugin policy");
    assert_eq!(close.reason.as_str(), "backend payload limit");
}

// ── permessage-deflate terminate keeps the configured reason ─────────────

#[test]
fn permessage_deflate_size_faults_keep_the_binding_plugin_reason() {
    let plugins = [limiter(json!({
        "max_frame_bytes": 1024,
        "max_message_bytes": 4096,
        "close_reason": "tenant payload limit",
        "backend_to_client": {"max_frame_bytes": 2048, "close_reason": "backend tenant limit"}
    }))];
    for fault in [
        PermessageDeflateFault::CompressedFrameTooLarge {
            size: 1025,
            max: 1024,
        },
        PermessageDeflateFault::DecompressedFrameTooLarge { max: 1024 },
        PermessageDeflateFault::DecompressedMessageTooLarge { max: 4096 },
    ] {
        let (close, plugin_bound) = ws_permessage_deflate_fault_close_for_test(
            1 << 20,
            &plugins,
            WebSocketFrameDirection::ClientToBackend,
            fault,
        );
        assert!(plugin_bound, "{fault:?} hit the plugin ceiling");
        assert_eq!(close.code, CloseCode::Size, "{fault:?}");
        assert_eq!(close.reason.as_str(), "tenant payload limit", "{fault:?}");
    }

    let (close, plugin_bound) = ws_permessage_deflate_fault_close_for_test(
        1 << 20,
        &plugins,
        WebSocketFrameDirection::BackendToClient,
        PermessageDeflateFault::DecompressedFrameTooLarge { max: 2048 },
    );
    assert!(plugin_bound);
    assert_eq!(close.reason.as_str(), "backend tenant limit");
}

#[test]
fn permessage_deflate_independent_ceilings_keep_the_fixed_reason() {
    let plugins = [limiter(json!({
        "max_frame_bytes": 1024,
        "max_message_bytes": 4096,
        "close_reason": "tenant payload limit"
    }))];
    // A stricter FERRUM_WEBSOCKET_PERMESSAGE_DEFLATE_MAX_MESSAGE_BYTES ceiling,
    // a global frame ceiling below the plugin's, and corrupt data are not the
    // plugin's decision.
    for (global_frame_bytes, fault) in [
        (
            1 << 20,
            PermessageDeflateFault::DecompressedMessageTooLarge { max: 2048 },
        ),
        (
            512,
            PermessageDeflateFault::DecompressedFrameTooLarge { max: 512 },
        ),
        (1 << 20, PermessageDeflateFault::InvalidCompressedData),
    ] {
        let (close, plugin_bound) = ws_permessage_deflate_fault_close_for_test(
            global_frame_bytes,
            &plugins,
            WebSocketFrameDirection::ClientToBackend,
            fault,
        );
        assert!(!plugin_bound, "{fault:?}");
        assert_eq!(close, fault.close_frame(), "{fault:?}");
    }
}

// ── ferrum_ws_message_size_limit_rejected_total ──────────────────────────

#[test]
fn size_limit_rejection_counter_is_exported_by_direction() {
    let registry = MetricsRegistry::new();
    registry.record_ws_message_size_limit_rejection(WebSocketFrameDirection::ClientToBackend);
    registry.record_ws_message_size_limit_rejection(WebSocketFrameDirection::ClientToBackend);
    registry.record_ws_message_size_limit_rejection(WebSocketFrameDirection::BackendToClient);
    assert_eq!(
        registry.ws_message_size_limit_rejections_total(WebSocketFrameDirection::ClientToBackend),
        2
    );
    assert_eq!(
        registry.ws_message_size_limit_rejections_total(WebSocketFrameDirection::BackendToClient),
        1
    );

    let output = registry.render_uncached();
    assert!(
        output.contains("# TYPE ferrum_ws_message_size_limit_rejected_total counter"),
        "{output}"
    );
    assert!(
        output.contains(
            "ferrum_ws_message_size_limit_rejected_total{direction=\"client_to_backend\"} 2"
        ),
        "{output}"
    );
    assert!(
        output.contains(
            "ferrum_ws_message_size_limit_rejected_total{direction=\"backend_to_client\"} 1"
        ),
        "{output}"
    );
}

// ── Docs parity: Ping/Pong count against max_frame_bytes ─────────────────

#[test]
fn docs_warn_that_ping_pong_count_against_the_frame_ceiling() {
    const PLUGINS_MD: &str = include_str!("../../../docs/plugins.md");
    const OPENAPI_YAML: &str = include_str!("../../../openapi.yaml");

    let start = PLUGINS_MD
        .find("### `ws_message_size_limiting`")
        .expect("plugin section exists");
    let section = &PLUGINS_MD[start..];
    let section = &section[..section[4..]
        .find("\n### ")
        .map(|end| end + 4)
        .unwrap_or(section.len())];
    let frame_row = section
        .lines()
        .find(|line| line.starts_with("| `max_frame_bytes` |"))
        .expect("max_frame_bytes parameter row");
    for needle in ["Ping", "Pong", "125", "heartbeat"] {
        assert!(
            frame_row.contains(needle),
            "docs/plugins.md max_frame_bytes row must mention {needle}: {frame_row}"
        );
    }
    for needle in ["client_to_backend", "backend_to_client"] {
        assert!(
            section.contains(&format!("| `{needle}` |")),
            "docs/plugins.md must document the {needle} override"
        );
    }
    assert!(
        section.contains("ferrum_ws_message_size_limit_rejected_total"),
        "docs/plugins.md must document the rejection counter"
    );

    let start = OPENAPI_YAML
        .find("    WsMessageSizeLimitingConfig:")
        .expect("OpenAPI schema exists");
    let schema = &OPENAPI_YAML[start..];
    let schema = &schema[..schema
        .find("    WsFrameLoggingConfig:")
        .unwrap_or(schema.len())];
    assert!(
        schema.contains("values") && schema.contains("below 125") && schema.contains("heartbeat"),
        "openapi.yaml must keep the Ping/Pong heartbeat warning"
    );
    assert!(schema.contains("WsMessageSizeLimitingDirectionConfig:"));
}
