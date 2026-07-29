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
        // Workload labels — must match the ProxyConfig selector below to
        // trigger workload-scoped resolution.
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
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
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
                    custom_env_tags: HashMap::new(),
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
                    custom_env_tags: HashMap::new(),
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

/// CFG-05 / XDS-02: a Kubernetes `networking.istio.io/v1beta1` ProxyConfig
/// object in a translation batch must land on the native mesh slice and
/// round-trip identically through the Ferrum `ProxyConfigsCarrier` ECDS path.
/// This is the deterministic proof that the watcher/translator ingestion path
/// affects both native and xDS-equivalent mesh slices (issue #2396).
#[test]
fn k8s_proxy_config_reaches_native_and_xds_equivalent_mesh_slices() {
    use std::collections::BTreeMap;

    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;
    use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
    use ferrum_edge::xds::{MeshSliceCarrier, apply_carrier, build_slice_carriers};

    let proxy_config = K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "ProxyConfig".to_string(),
        metadata: K8sMetadata {
            name: "api-defaults".to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec: serde_json::json!({
            "selector": {"matchLabels": {"app": "api"}},
            "concurrency": 4,
            "image": {"imageType": "distroless"},
            "environmentVariables": {"GOMAXPROCS": "4"},
            "tracing": {"sampling": 42.0}
        }),
        status: serde_json::Value::Object(serde_json::Map::new()),
    };

    let options = K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    );
    let translation =
        translate_k8s_objects(&[proxy_config], options).expect("ProxyConfig translation succeeds");
    let gateway_config = translation.config;
    assert_eq!(
        gateway_config
            .mesh
            .as_ref()
            .expect("mesh present")
            .proxy_configs
            .len(),
        1,
        "K8s ProxyConfig must populate mesh.proxy_configs"
    );

    let request = MeshSliceRequest {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        workload_spiffe_id: None,
        labels: BTreeMap::from([("app".to_string(), "api".to_string())]),
        cluster_domain: "cluster.local".to_string(),
        enforce_sidecar_egress: false,
        sidecar_egress_dry_run: false,
        enforce_sidecar_identity_narrowing: false,
        waypoint_name: None,
        ambient_udp_source_scoping: false,
        node_waypoint_capture_scoping: false,
    };
    let native = MeshSlice::from_gateway_config(&gateway_config, request);
    assert_eq!(native.proxy_configs.len(), 1);
    let resolved = native
        .resolved_proxy_config()
        .expect("selector-matching ProxyConfig must resolve");
    assert_eq!(resolved.tracing_sampling, Some(42.0));
    assert_eq!(resolved.concurrency, Some(4));
    assert_eq!(resolved.image.as_deref(), Some("distroless"));

    let carriers = build_slice_carriers(&native);
    let proxy_carrier = carriers
        .iter()
        .find(|c| matches!(c, MeshSliceCarrier::ProxyConfigs(_)))
        .expect("native slice must emit ProxyConfigsCarrier");
    let encoded = proxy_carrier
        .encode_value()
        .expect("ProxyConfigsCarrier encodes");
    let decoded = MeshSliceCarrier::decode(proxy_carrier.type_url(), &encoded)
        .expect("decode succeeds")
        .expect("recognized ProxyConfigs carrier");

    let mut xds_equivalent = MeshSlice {
        node_id: native.node_id.clone(),
        namespace: native.namespace.clone(),
        ..Default::default()
    };
    apply_carrier(&mut xds_equivalent, decoded);
    assert_eq!(
        xds_equivalent.proxy_configs, native.proxy_configs,
        "xDS ProxyConfigsCarrier must recover the same proxy_configs as native"
    );
    assert_eq!(
        xds_equivalent
            .resolved_proxy_config()
            .and_then(|pc| pc.tracing_sampling),
        Some(42.0)
    );
}

/// Now that the Kubernetes watcher can carry an operator-authored ProxyConfig
/// all the way to the injected `workload_metrics` plugin, an unusable
/// `spec.tracing.sampling` must fail closed at translation instead of being
/// silently dropped (non-numeric) or pushed through unvalidated
/// (out-of-range). This mirrors `Telemetry.tracing.randomSamplingPercentage`
/// and matches the documented "percentage 0-100" contract; the rejection is
/// what the Istio status writer surfaces as `FerrumAccepted=False`/`Invalid`.
#[test]
fn k8s_proxy_config_rejects_unusable_tracing_sampling() {
    use ferrum_edge::config_sources::k8s::{
        K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
    };
    use ferrum_edge::identity::spiffe::TrustDomain;

    fn proxy_config_with_sampling(sampling: serde_json::Value) -> K8sObject {
        K8sObject {
            api_version: "networking.istio.io/v1beta1".to_string(),
            kind: "ProxyConfig".to_string(),
            metadata: K8sMetadata {
                name: "api-defaults".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: serde_json::json!({ "tracing": { "sampling": sampling } }),
            status: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    fn options() -> K8sTranslationOptions {
        K8sTranslationOptions::new(
            "default".to_string(),
            TrustDomain::new("cluster.local").expect("test trust domain"),
        )
    }

    for rejected in [
        serde_json::json!(5000.0),
        serde_json::json!(-1.0),
        serde_json::json!("50"),
    ] {
        let object = proxy_config_with_sampling(rejected.clone());
        let result = translate_k8s_objects(&[object], options());
        let message = match result {
            Ok(_) => panic!("sampling {rejected} must be rejected, not translated"),
            Err(error) => error.to_string(),
        };
        assert!(
            message.contains("spec.tracing.sampling"),
            "rejection must name the offending field, got: {message}"
        );
    }

    // The inclusive bounds stay accepted.
    for accepted in [0.0_f64, 100.0_f64] {
        let object = proxy_config_with_sampling(serde_json::json!(accepted));
        let translation = match translate_k8s_objects(&[object], options()) {
            Ok(translation) => translation,
            Err(error) => panic!("sampling {accepted} must be accepted: {error}"),
        };
        let mesh = translation.config.mesh.expect("mesh present");
        assert_eq!(mesh.proxy_configs[0].tracing_sampling, Some(accepted));
    }
}
