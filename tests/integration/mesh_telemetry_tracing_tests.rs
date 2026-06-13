use chrono::Utc;
use std::collections::HashMap;
use std::net::SocketAddr;

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshTelemetryConfig, MeshTelemetryResource, MeshTracingConfig,
    OutboundTrafficPolicy, PolicyScope, TelemetryTracingMode, TracingProvider, WorkloadSelector,
};
use ferrum_edge::modes::mesh::{
    MESH_WORKLOAD_METRICS_PLUGIN_ID, MeshConfigProtocol, MeshRuntimeConfig, MeshTopology,
    MeshTrafficDirection, prepare_gateway_config_for_mesh,
};
use ferrum_edge::plugins::{TransactionSummary, create_plugin};
use serde_json::{Value, json};

fn test_addr(s: &str) -> SocketAddr {
    s.parse().expect("valid socket address")
}

fn test_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: test_addr("127.0.0.1:15006"),
        outbound_listen_addr: test_addr("127.0.0.1:15001"),
        hbone_listen_addr: test_addr("127.0.0.1:15008"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: test_addr("0.0.0.0:15090"),
        workload_spiffe_id: None,
        waypoint_name: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        dns_enabled: false,
        dns_listen_addr: test_addr("127.0.0.1:15053"),
        dns_upstream_addr: test_addr("127.0.0.53:53"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: false,
        request_auth_require_exp: true,
    }
}

fn traced_summary() -> TransactionSummary {
    TransactionSummary {
        namespace: "default".to_string(),
        timestamp_received: "2026-03-23T12:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        http_method: "GET".to_string(),
        request_path: "/reviews".to_string(),
        response_status_code: 200,
        latency_total_ms: 12.0,
        latency_gateway_processing_ms: 2.0,
        latency_backend_ttfb_ms: 5.0,
        latency_backend_total_ms: 10.0,
        metadata: HashMap::from([
            (
                "trace_id".to_string(),
                "abcdef1234567890abcdef1234567890".to_string(),
            ),
            ("span_id".to_string(), "1234567890abcdef".to_string()),
            ("trace_sampled".to_string(), "true".to_string()),
        ]),
        ..TransactionSummary::default()
    }
}

async fn received_json(server: &wiremock::MockServer) -> serde_json::Value {
    for _ in 0..30 {
        if let Some(requests) = server.received_requests().await
            && let Some(request) = requests.first()
        {
            return request.body_json().expect("valid JSON body");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("collector did not receive a span export");
}

async fn assert_no_requests(server: &wiremock::MockServer) {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(server.received_requests().await.unwrap().is_empty());
}

fn workload_metrics_plugin_config(tracing: MeshTracingConfig) -> Value {
    let mesh = MeshConfig {
        telemetry_resources: vec![MeshTelemetryResource {
            name: "api-tracing".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            config: MeshTelemetryConfig {
                tracing: Some(tracing),
                ..MeshTelemetryConfig::default()
            },
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let prepared =
        prepare_gateway_config_for_mesh(config, &test_runtime()).expect("mesh prepare succeeds");
    let mut plugin_config = prepared
        .plugin_configs
        .into_iter()
        .find(|plugin| plugin.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics injected");

    plugin_config.config["batch_size"] = json!(1);
    plugin_config.config["flush_interval_ms"] = json!(100);
    plugin_config.config["service_name"] = json!("reviews");
    plugin_config.config
}

fn otlp_resource_string_attr<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload["resourceSpans"][0]["resource"]["attributes"]
        .as_array()?
        .iter()
        .find(|attr| attr.get("key").and_then(Value::as_str) == Some(key))
        .and_then(|attr| attr.get("value"))
        .and_then(|value| value.get("stringValue")?.as_str())
}

#[tokio::test]
async fn telemetry_provider_from_mesh_slice_emits_otlp_span() {
    let collector = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&collector)
        .await;

    let plugin_config = workload_metrics_plugin_config(MeshTracingConfig {
        mode: None,
        sampling_percentage: Some(100.0),
        disable_span_reporting: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: vec![TracingProvider::OpenTelemetry {
            endpoint: format!("{}/v1/traces", collector.uri()),
        }],
    });

    let plugin = create_plugin("workload_metrics", &plugin_config)
        .expect("plugin creation succeeds")
        .expect("plugin exists");
    plugin.log(&traced_summary()).await;
    drop(plugin);

    let payload = received_json(&collector).await;
    assert_eq!(
        otlp_resource_string_attr(&payload, "service.name"),
        Some("reviews")
    );
    assert_eq!(
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"],
        "GET /reviews"
    );
}

#[tokio::test]
async fn telemetry_disable_span_reporting_from_mesh_slice_suppresses_export() {
    let collector = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(0)
        .mount(&collector)
        .await;

    let plugin_config = workload_metrics_plugin_config(MeshTracingConfig {
        mode: None,
        sampling_percentage: Some(100.0),
        disable_span_reporting: Some(true),
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: vec![TracingProvider::OpenTelemetry {
            endpoint: format!("{}/v1/traces", collector.uri()),
        }],
    });

    let plugin = create_plugin("workload_metrics", &plugin_config)
        .expect("plugin creation succeeds")
        .expect("plugin exists");
    plugin.log(&traced_summary()).await;
    drop(plugin);

    assert_no_requests(&collector).await;
}

fn traced_summary_with_direction(direction: Option<MeshTrafficDirection>) -> TransactionSummary {
    let mut summary = traced_summary();
    if let Some(dir) = direction {
        let value = match dir {
            MeshTrafficDirection::Inbound => "inbound",
            MeshTrafficDirection::Outbound => "outbound",
        };
        summary
            .metadata
            .insert("mesh.direction".to_string(), value.to_string());
    }
    summary
}

#[tokio::test]
async fn telemetry_tracing_mode_client_emits_kind_client_span_on_outbound_listener() {
    let collector = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&collector)
        .await;

    let plugin_config = workload_metrics_plugin_config(MeshTracingConfig {
        mode: Some(TelemetryTracingMode::Client),
        sampling_percentage: Some(100.0),
        disable_span_reporting: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: vec![TracingProvider::OpenTelemetry {
            endpoint: format!("{}/v1/traces", collector.uri()),
        }],
    });
    assert_eq!(
        plugin_config["direction_emit"],
        json!({ "server": false, "client": true })
    );

    let plugin = create_plugin("workload_metrics", &plugin_config)
        .expect("plugin creation succeeds")
        .expect("plugin exists");
    // An outbound-listener-stamped request: CLIENT-only plugin should export.
    plugin
        .log(&traced_summary_with_direction(Some(
            MeshTrafficDirection::Outbound,
        )))
        .await;
    drop(plugin);

    let payload = received_json(&collector).await;
    assert_eq!(
        payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"],
        json!(3),
        "CLIENT span emitted with OTLP kind=3"
    );
}

#[tokio::test]
async fn telemetry_tracing_mode_client_skips_inbound_listener_traffic() {
    let collector = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(0)
        .mount(&collector)
        .await;

    let plugin_config = workload_metrics_plugin_config(MeshTracingConfig {
        mode: Some(TelemetryTracingMode::Client),
        sampling_percentage: Some(100.0),
        disable_span_reporting: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: vec![TracingProvider::OpenTelemetry {
            endpoint: format!("{}/v1/traces", collector.uri()),
        }],
    });

    let plugin = create_plugin("workload_metrics", &plugin_config)
        .expect("plugin creation succeeds")
        .expect("plugin exists");
    // Inbound-listener-stamped request: a CLIENT-only plugin must not emit.
    plugin
        .log(&traced_summary_with_direction(Some(
            MeshTrafficDirection::Inbound,
        )))
        .await;
    drop(plugin);

    assert_no_requests(&collector).await;
}

#[tokio::test]
async fn telemetry_tracing_mode_client_and_server_emits_both_directions() {
    let collector = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(2)
        .mount(&collector)
        .await;

    let plugin_config = workload_metrics_plugin_config(MeshTracingConfig {
        mode: Some(TelemetryTracingMode::ClientAndServer),
        sampling_percentage: Some(100.0),
        disable_span_reporting: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: vec![TracingProvider::OpenTelemetry {
            endpoint: format!("{}/v1/traces", collector.uri()),
        }],
    });
    assert_eq!(
        plugin_config["direction_emit"],
        json!({ "server": true, "client": true })
    );

    let plugin = create_plugin("workload_metrics", &plugin_config)
        .expect("plugin creation succeeds")
        .expect("plugin exists");
    plugin
        .log(&traced_summary_with_direction(Some(
            MeshTrafficDirection::Inbound,
        )))
        .await;
    plugin
        .log(&traced_summary_with_direction(Some(
            MeshTrafficDirection::Outbound,
        )))
        .await;
    drop(plugin);

    // Wait for both batched exports to flush.
    for _ in 0..40 {
        if collector
            .received_requests()
            .await
            .map(|r| r.len())
            .unwrap_or(0)
            >= 2
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let requests = collector
        .received_requests()
        .await
        .expect("collector reachable");
    assert_eq!(requests.len(), 2, "both directions exported");
    let kinds: Vec<i64> = requests
        .iter()
        .map(|req| {
            let body: serde_json::Value = req.body_json().expect("valid JSON");
            body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["kind"]
                .as_i64()
                .expect("kind is an integer")
        })
        .collect();
    assert!(kinds.contains(&2), "SERVER span (OTLP kind=2) present");
    assert!(kinds.contains(&3), "CLIENT span (OTLP kind=3) present");
}

#[tokio::test]
async fn telemetry_tracing_mode_unset_defaults_to_server_only() {
    let collector = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(0)
        .mount(&collector)
        .await;

    let plugin_config = workload_metrics_plugin_config(MeshTracingConfig {
        mode: None,
        sampling_percentage: Some(100.0),
        disable_span_reporting: None,
        custom_tags: HashMap::new(),
        custom_header_tags: HashMap::new(),
        providers: vec![TracingProvider::OpenTelemetry {
            endpoint: format!("{}/v1/traces", collector.uri()),
        }],
    });
    // No direction_emit key in serialized config when tracing.mode is None —
    // plugin falls back to its server_only default.
    assert!(plugin_config.get("direction_emit").is_none());

    let plugin = create_plugin("workload_metrics", &plugin_config)
        .expect("plugin creation succeeds")
        .expect("plugin exists");
    // Outbound-stamped summary should be skipped by the SERVER-only default.
    plugin
        .log(&traced_summary_with_direction(Some(
            MeshTrafficDirection::Outbound,
        )))
        .await;
    drop(plugin);

    assert_no_requests(&collector).await;
}
