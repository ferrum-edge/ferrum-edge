//! Integration tests for Istio `ProxyConfig` CRD translation.
//!
//! These exercise the end-to-end slice → injected `workload_metrics` plugin
//! flow: a `MeshProxyConfig` with `tracing_sampling=N` must surface as
//! `sampling_percentage: N` in the injected `__mesh_workload_metrics` plugin
//! config when `prepare_gateway_config_for_mesh` runs.

use chrono::Utc;
use std::collections::HashMap;
use std::net::SocketAddr;

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshProxyConfig, MeshTelemetryConfig, MeshTelemetryResource, MeshTracingConfig,
    PolicyScope, WorkloadSelector,
};
use ferrum_edge::modes::mesh::{
    MESH_WORKLOAD_METRICS_PLUGIN_ID, MeshConfigProtocol, MeshRuntimeConfig, MeshTopology,
    prepare_gateway_config_for_mesh,
};

fn test_addr(s: &str) -> SocketAddr {
    s.parse().expect("valid socket address")
}

fn test_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
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
        // Workload labels — must match the ProxyConfig selector below to
        // trigger workload-scoped resolution.
        workload_labels: HashMap::from([("app".to_string(), "api".to_string())]),
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        dns_enabled: false,
        dns_listen_addr: test_addr("127.0.0.1:15053"),
        dns_upstream_addr: test_addr("127.0.0.53:53"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: false,
        request_auth_require_exp: true,
    }
}

#[test]
fn proxy_config_tracing_sampling_flows_into_workload_metrics_plugin() {
    // A ProxyConfig with tracing.sampling=42 must surface as
    // sampling_percentage: 42 in the injected workload_metrics plugin.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "api-defaults".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            concurrency: Some(4),
            image: Some("distroless".to_string()),
            environment: HashMap::from([("GOMAXPROCS".to_string(), "4".to_string())]),
            tracing_sampling: Some(42.0),
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    let sampling = metrics_plugin
        .config
        .get("sampling_percentage")
        .and_then(|v| v.as_f64())
        .expect("sampling_percentage populated from ProxyConfig");
    assert_eq!(sampling, 42.0);
}

#[test]
fn proxy_config_does_not_set_sampling_when_unset() {
    // A ProxyConfig with no tracing.sampling must not populate
    // sampling_percentage — the workload_metrics plugin defaults to 100.0
    // when unset.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "api-defaults".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            concurrency: Some(4),
            image: None,
            environment: HashMap::new(),
            tracing_sampling: None,
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    assert!(
        metrics_plugin.config.get("sampling_percentage").is_none(),
        "no sampling_percentage should be set when ProxyConfig.tracing_sampling is None"
    );
}

#[test]
fn telemetry_tracing_sampling_overrides_proxy_config_tracing_sampling() {
    // When BOTH a ProxyConfig and a Telemetry resource set a tracing
    // sampling value, the more granular Telemetry CRD must win on the
    // `sampling_percentage` key. This is the PR's stated merge contract.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "api-defaults".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: Some(10.0),
        }],
        telemetry_resources: vec![MeshTelemetryResource {
            name: "telemetry-default".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::Namespace {
                namespace: "default".to_string(),
            },
            config: MeshTelemetryConfig {
                tracing: Some(MeshTracingConfig {
                    mode: None,
                    sampling_percentage: Some(99.0),
                    disable_span_reporting: None,
                    custom_tags: HashMap::new(),
                    custom_header_tags: HashMap::new(),
                    providers: Vec::new(),
                }),
                metrics: None,
                access_logging: None,
            },
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    let sampling = metrics_plugin
        .config
        .get("sampling_percentage")
        .and_then(|v| v.as_f64())
        .expect("sampling_percentage populated");
    assert_eq!(
        sampling, 99.0,
        "Telemetry.tracing.sampling_percentage must override ProxyConfig.tracing_sampling"
    );
}

#[test]
fn proxy_config_tracing_sampling_survives_telemetry_without_sampling_field() {
    // When ProxyConfig sets sampling and Telemetry has tracing but does not
    // populate the sampling field (e.g., only custom_tags), the ProxyConfig
    // baseline must NOT be erased — Telemetry only overrides per-field.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "api-defaults".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: Some(25.0),
        }],
        telemetry_resources: vec![MeshTelemetryResource {
            name: "telemetry-tags-only".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::Namespace {
                namespace: "default".to_string(),
            },
            config: MeshTelemetryConfig {
                tracing: Some(MeshTracingConfig {
                    mode: None,
                    sampling_percentage: None,
                    disable_span_reporting: None,
                    custom_tags: HashMap::from([("region".to_string(), "us-east".to_string())]),
                    custom_header_tags: HashMap::new(),
                    providers: Vec::new(),
                }),
                metrics: None,
                access_logging: None,
            },
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    let sampling = metrics_plugin
        .config
        .get("sampling_percentage")
        .and_then(|v| v.as_f64())
        .expect("sampling_percentage must remain from ProxyConfig baseline");
    assert_eq!(
        sampling, 25.0,
        "ProxyConfig.tracing_sampling must survive Telemetry with no sampling field"
    );
}

#[test]
fn proxy_config_zero_sampling_is_applied_not_skipped() {
    // ProxyConfig with tracing_sampling=0.0 means "never sample" — it must
    // be propagated, not silently treated as unset. (A None-vs-Some(0.0)
    // mix-up here would cause a 0% intent to fall back to the plugin's
    // 100% default.)
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "no-tracing".to_string(),
            namespace: "default".to_string(),
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "api".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: Some(0.0),
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    let sampling = metrics_plugin
        .config
        .get("sampling_percentage")
        .and_then(|v| v.as_f64())
        .expect("sampling_percentage must be present for Some(0.0)");
    assert_eq!(
        sampling, 0.0,
        "ProxyConfig.tracing_sampling=Some(0.0) must propagate as 0.0, not be skipped"
    );
}

#[test]
fn proxy_config_non_matching_selector_does_not_apply() {
    // A ProxyConfig whose selector does not match the workload's labels
    // should be filtered out at slice construction time and have no
    // impact on the injected plugin.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "worker-defaults".to_string(),
            namespace: "default".to_string(),
            // Workload has `app=api` (see `test_runtime`), but this selector
            // requires `app=worker`.
            scope: PolicyScope::WorkloadSelector {
                selector: WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "worker".to_string())]),
                    namespace: Some("default".to_string()),
                },
            },
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: Some(75.0),
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    assert!(
        metrics_plugin.config.get("sampling_percentage").is_none(),
        "non-matching ProxyConfig must not contribute sampling"
    );
}

#[test]
fn mesh_wide_proxy_config_applies_to_workload_in_other_namespace() {
    // A ProxyConfig translated as PolicyScope::MeshWide (Istio
    // root-namespace + no selector) must apply to a workload in a
    // different namespace, surfacing as sampling_percentage on the
    // injected workload_metrics plugin.
    let mesh = MeshConfig {
        proxy_configs: vec![MeshProxyConfig {
            name: "mesh-default".to_string(),
            namespace: "istio-config".to_string(),
            scope: PolicyScope::MeshWide,
            concurrency: None,
            image: None,
            environment: HashMap::new(),
            tracing_sampling: Some(7.5),
        }],
        ..MeshConfig::default()
    };
    let config = GatewayConfig {
        mesh: Some(Box::new(mesh)),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let runtime = test_runtime();

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");

    let metrics_plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_WORKLOAD_METRICS_PLUGIN_ID)
        .expect("workload_metrics plugin injected");

    let sampling = metrics_plugin
        .config
        .get("sampling_percentage")
        .and_then(|v| v.as_f64())
        .expect("mesh-wide ProxyConfig must contribute sampling");
    assert_eq!(sampling, 7.5);
}
