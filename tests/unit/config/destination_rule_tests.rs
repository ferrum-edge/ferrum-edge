//! Tests for DestinationRule runtime support:
//! - SubsetDefinition / SubsetTrafficPolicy serde round-trip
//! - PassiveHealthCheck new fields serde
//! - Upstream subset validation (duplicate names, empty labels, max count)
//! - Proxy upstream_subset validation
//! - pool_max_requests_per_connection serde

use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, PassiveHealthCheck, Proxy, SubsetDefinition,
    SubsetTrafficPolicy, Upstream, UpstreamTarget,
};
use std::collections::HashMap;

// ── SubsetDefinition / SubsetTrafficPolicy serde ─────────────────────────────

#[test]
fn subset_definition_round_trip_json() {
    let subset = SubsetDefinition {
        name: "canary".into(),
        labels: HashMap::from([("version".into(), "v2".into())]),
        traffic_policy: Some(SubsetTrafficPolicy {
            load_balancer_algorithm: Some(LoadBalancerAlgorithm::Random),
            tls: None,
            connect_timeout_ms: None,
            passive_health_check: None,
        }),
    };

    let json = serde_json::to_string(&subset).unwrap();
    let deserialized: SubsetDefinition = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.name, "canary");
    assert_eq!(deserialized.labels.get("version").unwrap(), "v2");
    assert_eq!(
        deserialized
            .traffic_policy
            .as_ref()
            .unwrap()
            .load_balancer_algorithm,
        Some(LoadBalancerAlgorithm::Random)
    );
}

#[test]
fn subset_definition_without_traffic_policy() {
    let json = r#"{"name":"stable","labels":{"env":"prod"}}"#;
    let subset: SubsetDefinition = serde_json::from_str(json).unwrap();

    assert_eq!(subset.name, "stable");
    assert!(subset.traffic_policy.is_none());
}

#[test]
fn subset_definition_multi_label_selector() {
    let subset = SubsetDefinition {
        name: "prod-v3".into(),
        labels: HashMap::from([
            ("env".into(), "production".into()),
            ("version".into(), "v3".into()),
        ]),
        traffic_policy: None,
    };

    let json = serde_json::to_string(&subset).unwrap();
    let back: SubsetDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(back.labels.len(), 2);
    assert_eq!(back.labels["env"], "production");
    assert_eq!(back.labels["version"], "v3");
}

#[test]
fn subset_traffic_policy_omits_none_fields() {
    let policy = SubsetTrafficPolicy {
        load_balancer_algorithm: None,
        tls: None,
        connect_timeout_ms: None,
        passive_health_check: None,
    };
    let json = serde_json::to_string(&policy).unwrap();
    // skip_serializing_if = "Option::is_none" should omit both optional fields,
    // producing a wire-compatible empty object.
    assert!(!json.contains("load_balancer_algorithm"));
    assert!(!json.contains("\"tls\""));
    assert_eq!(json, "{}");
}

#[test]
fn subset_traffic_policy_tls_round_trip_json() {
    use ferrum_edge::modes::mesh::config::{MeshTrafficPolicyTls, MtlsMode};

    let policy = SubsetTrafficPolicy {
        load_balancer_algorithm: None,
        tls: Some(MeshTrafficPolicyTls {
            mode: MtlsMode::Mutual,
            ca_certificates: Some("/etc/certs/subset-ca.pem".into()),
            client_certificate: Some("/etc/certs/subset-client.pem".into()),
            private_key: Some("/etc/certs/subset-client.key".into()),
            sni: Some("subset.mesh.internal".into()),
            subject_alt_names: vec!["spiffe://mesh.local/ns/default/sa/canary".into()],
            insecure_skip_verify: false,
        }),
        connect_timeout_ms: None,
        passive_health_check: None,
    };

    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("\"tls\""));
    assert!(json.contains("\"ca_certificates\""));
    assert!(json.contains("\"subject_alt_names\""));

    let back: SubsetTrafficPolicy = serde_json::from_str(&json).unwrap();
    let tls = back.tls.expect("subset tls round-trips");
    assert_eq!(tls.mode, MtlsMode::Mutual);
    assert_eq!(
        tls.ca_certificates.as_deref(),
        Some("/etc/certs/subset-ca.pem")
    );
    assert_eq!(
        tls.client_certificate.as_deref(),
        Some("/etc/certs/subset-client.pem")
    );
    assert_eq!(
        tls.private_key.as_deref(),
        Some("/etc/certs/subset-client.key")
    );
    assert_eq!(tls.sni.as_deref(), Some("subset.mesh.internal"));
    assert_eq!(
        tls.subject_alt_names,
        vec!["spiffe://mesh.local/ns/default/sa/canary".to_string()]
    );
    assert!(!tls.insecure_skip_verify);
}

// ── PassiveHealthCheck new fields serde ───────────────────────────────────────

#[test]
fn passive_health_check_default_omits_new_fields() {
    let phc = PassiveHealthCheck::default();
    assert!(phc.max_ejection_percent.is_none());
    assert!(phc.gateway_error_codes.is_none());
    assert!(phc.split_external_local_origin_errors.is_none());
}

#[test]
fn passive_health_check_with_new_fields_round_trip() {
    let phc = PassiveHealthCheck {
        max_ejection_percent: Some(50),
        gateway_error_codes: Some(vec![502, 503, 504]),
        split_external_local_origin_errors: Some(true),
        ..Default::default()
    };

    let json = serde_json::to_string(&phc).unwrap();
    let back: PassiveHealthCheck = serde_json::from_str(&json).unwrap();

    assert_eq!(back.max_ejection_percent, Some(50));
    assert_eq!(back.gateway_error_codes, Some(vec![502, 503, 504]));
    assert_eq!(back.split_external_local_origin_errors, Some(true));
}

#[test]
fn passive_health_check_skip_serializing_none_fields() {
    let phc = PassiveHealthCheck::default();
    let json = serde_json::to_string(&phc).unwrap();
    assert!(!json.contains("max_ejection_percent"));
    assert!(!json.contains("gateway_error_codes"));
    assert!(!json.contains("split_external_local_origin_errors"));
}

// ── Upstream subset validation ───────────────────────────────────────────────

fn make_upstream(subsets: Option<Vec<SubsetDefinition>>) -> Upstream {
    Upstream {
        id: "u1".into(),
        namespace: "ferrum".into(),
        name: Some("test-upstream".into()),
        targets: vec![UpstreamTarget {
            host: "10.0.0.1".into(),
            port: 8080,
            weight: 1,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn upstream_validates_duplicate_subset_names() {
    let u = make_upstream(Some(vec![
        SubsetDefinition {
            name: "canary".into(),
            labels: HashMap::from([("v".into(), "1".into())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "canary".into(),
            labels: HashMap::from([("v".into(), "2".into())]),
            traffic_policy: None,
        },
    ]));

    let errors = u.validate_fields().unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("duplicate")),
        "Expected duplicate subset name error, got: {:?}",
        errors
    );
}

#[test]
fn upstream_validates_empty_subset_labels() {
    let u = make_upstream(Some(vec![SubsetDefinition {
        name: "empty-labels".into(),
        labels: HashMap::new(),
        traffic_policy: None,
    }]));

    let errors = u.validate_fields().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("labels must not be empty")),
        "Expected empty labels error, got: {:?}",
        errors
    );
}

#[test]
fn upstream_validates_empty_subset_name() {
    let u = make_upstream(Some(vec![SubsetDefinition {
        name: "".into(),
        labels: HashMap::from([("v".into(), "1".into())]),
        traffic_policy: None,
    }]));

    let errors = u.validate_fields().unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("name must not be empty")),
        "Expected empty name error, got: {:?}",
        errors
    );
}

#[test]
fn upstream_validates_too_many_subsets() {
    let subsets: Vec<SubsetDefinition> = (0..101)
        .map(|i| SubsetDefinition {
            name: format!("subset-{}", i),
            labels: HashMap::from([("idx".into(), i.to_string())]),
            traffic_policy: None,
        })
        .collect();

    let u = make_upstream(Some(subsets));
    let errors = u.validate_fields().unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("must not have more than")),
        "Expected max subsets error, got: {:?}",
        errors
    );
}

#[test]
fn upstream_rejects_empty_subset_list() {
    let u = make_upstream(Some(vec![]));
    let errors = u.validate_fields().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("subsets must not be empty")),
        "Expected empty subset list error, got: {:?}",
        errors
    );
}

#[test]
fn upstream_valid_subsets_pass_validation() {
    let u = make_upstream(Some(vec![
        SubsetDefinition {
            name: "stable".into(),
            labels: HashMap::from([("version".into(), "v1".into())]),
            traffic_policy: None,
        },
        SubsetDefinition {
            name: "canary".into(),
            labels: HashMap::from([("version".into(), "v2".into())]),
            traffic_policy: Some(SubsetTrafficPolicy {
                load_balancer_algorithm: Some(LoadBalancerAlgorithm::Random),
                tls: None,
                connect_timeout_ms: None,
                passive_health_check: None,
            }),
        },
    ]));

    assert!(
        u.validate_fields().is_ok(),
        "Expected no errors for valid subsets"
    );
}

// ── PassiveHealthCheck max_ejection_percent validation ────────────────────────

#[test]
fn passive_health_check_validates_ejection_percent_over_100() {
    // The validation lives inside HealthCheckConfig.validate_fields() which wraps
    // the passive config. Build a HealthCheckConfig with an invalid percentage.
    use ferrum_edge::config::types::HealthCheckConfig;

    let hc = HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(101),
            ..Default::default()
        }),
    };

    let result = hc.validate_fields();
    let errors = result.unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("max_ejection_percent must be between")),
        "Expected max_ejection_percent validation error, got: {:?}",
        errors
    );
}

#[test]
fn passive_health_check_valid_ejection_percent_passes() {
    use ferrum_edge::config::types::HealthCheckConfig;

    let hc = HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(50),
            ..Default::default()
        }),
    };

    assert!(
        hc.validate_fields().is_ok(),
        "Expected no errors for valid ejection percent"
    );
}

#[test]
fn passive_health_check_zero_ejection_percent_passes() {
    use ferrum_edge::config::types::HealthCheckConfig;

    let hc = HealthCheckConfig {
        active: None,
        passive: Some(PassiveHealthCheck {
            max_ejection_percent: Some(0),
            ..Default::default()
        }),
    };

    assert!(
        hc.validate_fields().is_ok(),
        "Expected no errors for 0% ejection cap"
    );
}

// ── pool_max_requests_per_connection serde ────────────────────────────────────

#[test]
fn proxy_pool_max_requests_defaults_to_none() {
    let json = r#"{
        "id": "p1",
        "listen_path": "/test",
        "backend_host": "localhost",
        "backend_port": 8080
    }"#;

    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_str(json).unwrap();
    assert!(proxy.pool_max_requests_per_connection.is_none());
}

#[test]
fn proxy_pool_max_requests_round_trip() {
    let json = r#"{
        "id": "p1",
        "listen_path": "/test",
        "backend_host": "localhost",
        "backend_port": 8080,
        "pool_max_requests_per_connection": 1000
    }"#;

    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.pool_max_requests_per_connection, Some(1000));

    let back_json = serde_json::to_string(&proxy).unwrap();
    assert!(back_json.contains("\"pool_max_requests_per_connection\":1000"));
}

#[test]
fn proxy_pool_max_requests_zero_means_unlimited() {
    let json = r#"{
        "id": "p1",
        "listen_path": "/test",
        "backend_host": "localhost",
        "backend_port": 8080,
        "pool_max_requests_per_connection": 0
    }"#;

    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.pool_max_requests_per_connection, Some(0));
    assert!(
        proxy.validate_fields().is_ok(),
        "0 is Istio's explicit unlimited value and should validate"
    );
}

#[test]
fn proxy_upstream_subset_defaults_to_none() {
    let json = r#"{
        "id": "p1",
        "listen_path": "/test",
        "backend_host": "localhost",
        "backend_port": 8080
    }"#;

    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_str(json).unwrap();
    assert!(proxy.upstream_subset.is_none());
}

#[test]
fn proxy_upstream_subset_round_trip() {
    let json = r#"{
        "id": "p1",
        "listen_path": "/test",
        "backend_host": "localhost",
        "backend_port": 8080,
        "upstream_id": "u1",
        "upstream_subset": "canary"
    }"#;

    let proxy: ferrum_edge::config::types::Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.upstream_subset.as_deref(), Some("canary"));
}

#[test]
fn proxy_upstream_subset_rejects_udp_and_dtls_until_runtime_supports_it() {
    for scheme in ["udp", "dtls"] {
        let json = serde_json::json!({
            "id": format!("p-{scheme}"),
            "backend_scheme": scheme,
            "listen_port": 5353,
            "backend_host": "localhost",
            "backend_port": 5353,
            "upstream_id": "u1",
            "upstream_subset": "stable"
        });

        let proxy: Proxy = serde_json::from_value(json).unwrap();
        let errors = proxy.validate_fields().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| e.contains("upstream_subset is not supported for udp/dtls")),
            "expected UDP/DTLS subset rejection for {scheme}, got: {errors:?}"
        );
    }
}

#[test]
fn gateway_config_validates_proxy_subset_reference() {
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "p1",
            "listen_path": "/test",
            "backend_host": "localhost",
            "backend_port": 8080,
            "upstream_id": "u1",
            "upstream_subset": "missing"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [{
            "id": "u1",
            "targets": [{
                "host": "10.0.0.1",
                "port": 8080,
                "tags": {"version": "v1"}
            }],
            "subsets": [{
                "name": "stable",
                "labels": {"version": "v1"}
            }]
        }]
    }))
    .unwrap();

    let errors = config.validate_upstream_references().unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| { e.contains("upstream_subset 'missing'") && e.contains("upstream_id 'u1'") }),
        "Expected missing subset reference error, got: {:?}",
        errors
    );
}

#[test]
fn gateway_config_accepts_valid_proxy_subset_reference() {
    let config: GatewayConfig = serde_json::from_value(serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "p1",
            "listen_path": "/test",
            "backend_host": "localhost",
            "backend_port": 8080,
            "upstream_id": "u1",
            "upstream_subset": "stable"
        }],
        "consumers": [],
        "plugin_configs": [],
        "upstreams": [{
            "id": "u1",
            "targets": [{
                "host": "10.0.0.1",
                "port": 8080,
                "tags": {"version": "v1"}
            }],
            "subsets": [{
                "name": "stable",
                "labels": {"version": "v1"}
            }]
        }]
    }))
    .unwrap();

    assert!(config.validate_upstream_references().is_ok());
}

// ── UpstreamPortOverride max_connections / tcp_keepalive serde ────────────────

#[test]
fn upstream_port_override_max_connections_round_trips() {
    use ferrum_edge::config::types::{TcpKeepaliveCfg, UpstreamPortOverride};

    let override_slot = UpstreamPortOverride {
        max_connections: Some(50),
        tcp_keepalive: Some(TcpKeepaliveCfg {
            time_seconds: Some(300),
            interval_seconds: Some(30),
            probes: Some(3),
        }),
        ..UpstreamPortOverride::default()
    };
    let json = serde_json::to_string(&override_slot).unwrap();
    assert!(json.contains("\"max_connections\":50"));
    assert!(json.contains("\"tcp_keepalive\""));

    let back: UpstreamPortOverride = serde_json::from_str(&json).unwrap();
    assert_eq!(back.max_connections, Some(50));
    let keepalive = back.tcp_keepalive.expect("keepalive round-trips");
    assert_eq!(keepalive.time_seconds, Some(300));
    assert_eq!(keepalive.interval_seconds, Some(30));
    assert_eq!(keepalive.probes, Some(3));
}

#[test]
fn upstream_port_override_default_omits_new_fields_from_json() {
    use ferrum_edge::config::types::UpstreamPortOverride;

    // Wire compatibility: an `UpstreamPortOverride::default()` MUST omit
    // both new fields from the JSON shape so old DPs reading new slices see
    // the same byte-for-byte serialization as before.
    let empty = UpstreamPortOverride::default();
    let json = serde_json::to_string(&empty).unwrap();
    assert!(
        !json.contains("max_connections"),
        "max_connections=None must NOT appear in JSON: {json}"
    );
    assert!(
        !json.contains("tcp_keepalive"),
        "tcp_keepalive=None must NOT appear in JSON: {json}"
    );
    assert_eq!(
        json, "{}",
        "default override must serialize to empty object"
    );
}

#[test]
fn tcp_keepalive_cfg_partial_fields_round_trip() {
    use ferrum_edge::config::types::TcpKeepaliveCfg;

    // Each field is independently optional. A keepalive cfg with only
    // `time_seconds` must round-trip without resurrecting None fields.
    let cfg = TcpKeepaliveCfg {
        time_seconds: Some(600),
        ..TcpKeepaliveCfg::default()
    };
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"time_seconds\":600"));
    assert!(!json.contains("interval_seconds"));
    assert!(!json.contains("probes"));

    let back: TcpKeepaliveCfg = serde_json::from_str(&json).unwrap();
    assert_eq!(back.time_seconds, Some(600));
    assert!(back.interval_seconds.is_none());
    assert!(back.probes.is_none());
}

#[test]
fn tcp_keepalive_cfg_is_empty_recognises_all_none() {
    use ferrum_edge::config::types::TcpKeepaliveCfg;
    assert!(TcpKeepaliveCfg::default().is_empty());
    assert!(
        !TcpKeepaliveCfg {
            probes: Some(1),
            ..TcpKeepaliveCfg::default()
        }
        .is_empty()
    );
}
