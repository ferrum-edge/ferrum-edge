use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, Consumer, DispatchKind, GatewayConfig,
    LocalityPreference, MeshSdConfig, PluginAssociation, PluginConfig, PluginScope, Proxy,
    ResolvedPortOverride, ResolvedSubsetTrafficPolicy, RetryConfig, SdProvider,
    ServiceDiscoveryConfig, Upstream, UpstreamPortOverride, UpstreamTarget, hosts_overlap,
    validate_host_entry, validate_resource_id, wildcard_matches,
};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshTracingConfig, ServicePort, TracingProvider,
};
use std::collections::HashMap;

/// Helper to create a minimal proxy with required fields.
fn make_proxy(id: &str, listen_path: &str) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some(listen_path.to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "localhost".into(),
        backend_port: 3000,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],

        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        pool_tcp_keepalive_seconds: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create a minimal consumer.
fn make_consumer(id: &str, username: &str) -> Consumer {
    Consumer {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.into(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// Helper to create a minimal upstream.
fn make_upstream(id: &str) -> Upstream {
    Upstream {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        targets: vec![UpstreamTarget {
            host: "localhost".into(),
            port: 3000,
            service_port_policy_key: None,
            weight: 100,
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: Default::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn upstream_target_service_port_policy_key_is_derived_not_serialized() {
    let target = UpstreamTarget {
        host: "10.0.0.1".to_string(),
        port: 8080,
        service_port_policy_key: Some(80),
        weight: 1,
        tags: HashMap::new(),
        locality: None,
        path: None,
    };

    let serialized = serde_json::to_value(&target).expect("serialize target");
    assert!(
        serialized.get("service_port_policy_key").is_none(),
        "derived policy key must not be emitted into config JSON"
    );

    let deserialized: UpstreamTarget = serde_json::from_value(serde_json::json!({
        "host": "10.0.0.1",
        "port": 8080,
        "service_port_policy_key": 80,
        "weight": 1
    }))
    .expect("deserialize target");
    assert!(
        deserialized.service_port_policy_key.is_none(),
        "config JSON must not be able to set the derived policy key"
    );
}

#[test]
fn upstream_backend_tls_sni_and_sans_round_trip_through_serde() {
    let mut upstream = make_upstream("tls-upstream");
    upstream.backend_tls_sni = Some("reviews.mesh.internal".to_string());
    upstream.backend_tls_san_allow_list = vec![
        "reviews.mesh.internal".to_string(),
        "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
    ];

    let json = serde_json::to_string(&upstream).expect("serialize upstream");
    let parsed: Upstream = serde_json::from_str(&json).expect("deserialize upstream");

    assert_eq!(
        parsed.backend_tls_sni.as_deref(),
        Some("reviews.mesh.internal")
    );
    assert_eq!(
        parsed.backend_tls_san_allow_list,
        upstream.backend_tls_san_allow_list
    );
}

#[test]
fn upstream_backend_tls_new_fields_default_when_absent() {
    let upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "old-upstream",
        "targets": [{"host": "reviews.default.svc.cluster.local", "port": 8080}]
    }))
    .expect("old upstream shape should deserialize");

    assert!(upstream.backend_tls_sni.is_none());
    assert!(upstream.backend_tls_san_allow_list.is_empty());
    assert!(upstream.source_locality.is_none());
    assert!(upstream.locality_lb_setting.is_none());
    assert!(upstream.targets[0].locality.is_none());

    let json = serde_json::to_value(&upstream).expect("serialize upstream");
    let object = json.as_object().expect("upstream object");
    assert!(!object.contains_key("backend_tls_sni"));
    assert!(!object.contains_key("backend_tls_san_allow_list"));
    assert!(!object.contains_key("source_locality"));
    assert!(
        !object.contains_key("locality_lb_setting"),
        "locality_lb_setting must be omitted from serialized JSON when None"
    );
    assert!(
        !object["targets"][0]
            .as_object()
            .expect("target object")
            .contains_key("locality")
    );
}

#[test]
fn upstream_locality_lb_setting_round_trips_through_serde() {
    use std::collections::BTreeMap;

    use ferrum_edge::config::types::{
        LocalityDistribute, LocalityFailover, UpstreamLocalityLbSetting,
    };

    let mut upstream: Upstream = serde_json::from_value(serde_json::json!({
        "id": "u",
        "targets": [{"host": "reviews", "port": 8080}]
    }))
    .expect("upstream deserialize");
    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 80u32);
    to.insert("us-east".to_string(), 20u32);
    upstream.locality_lb_setting = Some(UpstreamLocalityLbSetting {
        enabled: true,
        distribute: vec![LocalityDistribute {
            from: "us-west/us-west-1/a".to_string(),
            to,
        }],
        failover: vec![LocalityFailover {
            from: "us-west".to_string(),
            to: "us-east".to_string(),
        }],
    });

    let json = serde_json::to_value(&upstream).expect("serialize upstream");
    let setting = json
        .as_object()
        .expect("object")
        .get("locality_lb_setting")
        .expect("locality_lb_setting present in JSON")
        .as_object()
        .expect("locality_lb_setting object");
    assert_eq!(setting.get("enabled"), Some(&serde_json::json!(true)));
    let distribute = setting
        .get("distribute")
        .expect("distribute key")
        .as_array();
    assert_eq!(distribute.map(|a| a.len()), Some(1));

    let round_tripped: Upstream = serde_json::from_value(json).expect("round-trip");
    let setting = round_tripped
        .locality_lb_setting
        .as_ref()
        .expect("setting round-trips");
    assert!(setting.enabled);
    assert_eq!(setting.distribute.len(), 1);
    assert_eq!(setting.distribute[0].from, "us-west/us-west-1/a");
    assert_eq!(setting.distribute[0].to.get("us-west"), Some(&80u32));
    assert_eq!(setting.distribute[0].to.get("us-east"), Some(&20u32));
    assert_eq!(setting.failover.len(), 1);
    assert_eq!(setting.failover[0].from, "us-west");
    assert_eq!(setting.failover[0].to, "us-east");
}

#[test]
fn upstream_port_override_locality_lb_setting_round_trips_through_serde() {
    use std::collections::BTreeMap;

    use ferrum_edge::config::types::{
        LocalityDistribute, LocalityFailover, UpstreamLocalityLbSetting, UpstreamPortOverride,
    };

    // Default UpstreamPortOverride has no locality_lb_setting and must omit
    // the key when serialized so old DPs reading new slices see a no-op.
    let default_override = UpstreamPortOverride::default();
    let default_json = serde_json::to_value(&default_override).expect("serialize default");
    let object = default_json.as_object().expect("object");
    assert!(
        !object.contains_key("locality_lb_setting"),
        "UpstreamPortOverride.locality_lb_setting must be omitted when None"
    );

    let mut to = BTreeMap::new();
    to.insert("us-west".to_string(), 70u32);
    to.insert("us-east".to_string(), 30u32);
    let override_with_locality = UpstreamPortOverride {
        locality_lb_setting: Some(UpstreamLocalityLbSetting {
            enabled: true,
            distribute: vec![LocalityDistribute {
                from: "us-west/us-west-1/a".to_string(),
                to,
            }],
            failover: vec![LocalityFailover {
                from: "us-west".to_string(),
                to: "us-east".to_string(),
            }],
        }),
        ..UpstreamPortOverride::default()
    };

    let json = serde_json::to_value(&override_with_locality).expect("serialize override");
    let object = json.as_object().expect("object");
    assert!(
        object.contains_key("locality_lb_setting"),
        "locality_lb_setting must be present when Some"
    );

    let round_tripped: UpstreamPortOverride =
        serde_json::from_value(json).expect("round-trip override");
    let setting = round_tripped
        .locality_lb_setting
        .as_ref()
        .expect("locality_lb_setting present after round-trip");
    assert!(setting.enabled);
    assert_eq!(setting.distribute.len(), 1);
    assert_eq!(setting.distribute[0].from, "us-west/us-west-1/a");
    assert_eq!(setting.distribute[0].to.get("us-west"), Some(&70u32));
    assert_eq!(setting.failover[0].from, "us-west");
    assert_eq!(setting.failover[0].to, "us-east");
}

#[test]
fn upstream_port_override_connection_pool_http_fields_round_trip_through_serde() {
    use ferrum_edge::config::types::UpstreamPortOverride;

    // Default omits the three new HTTP fields so old DPs reading new slices
    // see a no-op (wire-compatibility invariant for `#[serde(default,
    // skip_serializing_if = "Option::is_none")]`).
    let default_override = UpstreamPortOverride::default();
    let default_json = serde_json::to_value(&default_override).expect("serialize default");
    let object = default_json.as_object().expect("object");
    for field in [
        "http_max_requests_per_connection",
        "http_idle_timeout_ms",
        "h2_max_concurrent_streams",
    ] {
        assert!(
            !object.contains_key(field),
            "UpstreamPortOverride.{field} must be omitted when None (wire compatibility)"
        );
    }

    // Round-trip with each field set independently — verifies that partial
    // overlays don't auto-fill the other fields.
    let override_with_http = UpstreamPortOverride {
        http_max_requests_per_connection: Some(100),
        http_idle_timeout_ms: Some(90_000),
        h2_max_concurrent_streams: Some(500),
        ..UpstreamPortOverride::default()
    };
    let json = serde_json::to_value(&override_with_http).expect("serialize override");
    let object = json.as_object().expect("object");
    assert_eq!(
        object.get("http_max_requests_per_connection"),
        Some(&serde_json::json!(100))
    );
    assert_eq!(
        object.get("http_idle_timeout_ms"),
        Some(&serde_json::json!(90_000))
    );
    assert_eq!(
        object.get("h2_max_concurrent_streams"),
        Some(&serde_json::json!(500))
    );

    let round_tripped: UpstreamPortOverride =
        serde_json::from_value(json).expect("round-trip override");
    assert_eq!(round_tripped.http_max_requests_per_connection, Some(100));
    assert_eq!(round_tripped.http_idle_timeout_ms, Some(90_000));
    assert_eq!(round_tripped.h2_max_concurrent_streams, Some(500));
}

/// codex round-3 Finding 3: `H2UpgradePolicy` must deserialize from the
/// operator-facing Istio spelling (`DO_NOT_UPGRADE`, SCREAMING_SNAKE_CASE, like
/// the sibling `MeshSimpleLb`) — not the Rust variant name `DoNotUpgrade` — so a
/// native/file mesh slice (`FERRUM_MESH_CONFIG_PROTOCOL=file`) or an xDS carrier
/// authored with the Istio value parses. The snake alias is also accepted.
#[test]
fn h2_upgrade_policy_serde_uses_istio_screaming_names_with_snake_alias() {
    use ferrum_edge::config::types::H2UpgradePolicy;

    // Istio SCREAMING_SNAKE_CASE form (the canonical operator-facing spelling).
    for (s, expected) in [
        ("\"DEFAULT\"", H2UpgradePolicy::Default),
        ("\"UPGRADE\"", H2UpgradePolicy::Upgrade),
        ("\"DO_NOT_UPGRADE\"", H2UpgradePolicy::DoNotUpgrade),
    ] {
        let parsed: H2UpgradePolicy = serde_json::from_str(s).expect("parse SCREAMING form");
        assert_eq!(parsed, expected, "SCREAMING form {s} must parse");
    }

    // snake_case aliases also accepted for ergonomics.
    for (s, expected) in [
        ("\"default\"", H2UpgradePolicy::Default),
        ("\"upgrade\"", H2UpgradePolicy::Upgrade),
        ("\"do_not_upgrade\"", H2UpgradePolicy::DoNotUpgrade),
    ] {
        let parsed: H2UpgradePolicy = serde_json::from_str(s).expect("parse snake alias");
        assert_eq!(parsed, expected, "snake alias {s} must parse");
    }

    // Serialization emits the canonical SCREAMING form (carrier round-trip).
    assert_eq!(
        serde_json::to_value(H2UpgradePolicy::DoNotUpgrade).expect("serialize"),
        serde_json::json!("DO_NOT_UPGRADE")
    );

    // The real file-config path: `MeshConnectionPoolHttp.h2_upgrade_policy`
    // deserialized with the Istio value must land on `DoNotUpgrade`.
    use ferrum_edge::modes::mesh::config::MeshConnectionPoolHttp;
    let http: MeshConnectionPoolHttp = serde_json::from_value(serde_json::json!({
        "h2_upgrade_policy": "DO_NOT_UPGRADE",
    }))
    .expect("MeshConnectionPoolHttp deserializes the Istio value");
    assert_eq!(http.h2_upgrade_policy, Some(H2UpgradePolicy::DoNotUpgrade));
}

#[test]
fn resolved_port_override_from_upstream_override_projects_http_fields() {
    use ferrum_edge::config::types::{ResolvedPortOverride, UpstreamPortOverride};

    let port_override = UpstreamPortOverride {
        http_max_requests_per_connection: Some(40),
        http_idle_timeout_ms: Some(60_000),
        h2_max_concurrent_streams: Some(250),
        ..UpstreamPortOverride::default()
    };

    let resolved = ResolvedPortOverride::from_upstream_override(&port_override)
        .expect("non-empty overlay produces Some");
    assert_eq!(resolved.http_max_requests_per_connection, Some(40));
    assert_eq!(resolved.http_idle_timeout_ms, Some(60_000));
    assert_eq!(resolved.h2_max_concurrent_streams, Some(250));

    // Empty overlay returns None so empty entries don't bloat
    // `Proxy.dispatch_port_overrides`.
    let empty = UpstreamPortOverride::default();
    assert!(
        ResolvedPortOverride::from_upstream_override(&empty).is_none(),
        "empty overlay must collapse to None"
    );
}

#[test]
fn seed_connection_pool_http_from_fallback_merges_field_by_field() {
    use ferrum_edge::config::types::ResolvedPortOverride;

    // Per-port entry sets connectTimeout + one connectionPool.http field; the
    // remaining http fields must be inherited from the SD top-level fallback and
    // the per-port-set field must win. Non-http fields are untouched. This is the
    // exact field-level merge `resolve_effective_proxy_for_target` performs for
    // an SD upstream under Ferrum's documented connectionPool semantics.
    let mut per_port = ResolvedPortOverride {
        connect_timeout_ms: Some(750),
        h2_max_concurrent_streams: Some(10),
        ..ResolvedPortOverride::default()
    };
    let fallback = ResolvedPortOverride {
        h2_max_concurrent_streams: Some(64),
        http_idle_timeout_ms: Some(120_000),
        max_retries: Some(2),
        http1_max_pending_requests: Some(32),
        ..ResolvedPortOverride::default()
    };

    per_port.seed_connection_pool_http_from_fallback(&fallback);

    // Per-port field wins.
    assert_eq!(per_port.h2_max_concurrent_streams, Some(10));
    // Unset http fields inherited from the fallback.
    assert_eq!(per_port.http_idle_timeout_ms, Some(120_000));
    assert_eq!(per_port.max_retries, Some(2));
    assert_eq!(per_port.http1_max_pending_requests, Some(32));
    // Non-connectionPool.http field untouched (fallback never carries it).
    assert_eq!(per_port.connect_timeout_ms, Some(750));
}

#[test]
fn resolve_upstream_tls_projects_sni_and_sans_to_proxy_cache() {
    let mut upstream = make_upstream("reviews-u");
    upstream.backend_tls_sni = Some("reviews.mesh.internal".to_string());
    upstream.backend_tls_san_allow_list =
        vec!["spiffe://cluster.local/ns/default/sa/reviews".to_string()];
    let mut proxy = make_proxy("reviews-p", "/reviews");
    proxy.upstream_id = Some("reviews-u".to_string());

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..empty_config()
    };
    config.resolve_upstream_tls();

    let resolved = &config.proxies[0].resolved_tls;
    assert_eq!(resolved.sni.as_deref(), Some("reviews.mesh.internal"));
    assert_eq!(
        resolved.san_allow_list,
        vec!["spiffe://cluster.local/ns/default/sa/reviews".to_string()]
    );
}

#[test]
fn normalize_fields_rebuilds_upstream_resolved_tls_after_serde_round_trip() {
    let mut upstream = make_upstream("reviews-u");
    upstream.backend_tls_sni = Some("Reviews.Mesh.Internal".to_string());
    upstream.backend_tls_san_allow_list = vec!["Reviews.Mesh.Internal".to_string()];
    let mut proxy = make_proxy("reviews-p", "/reviews");
    proxy.upstream_id = Some("reviews-u".to_string());
    proxy.resolved_tls.sni = Some("stale.example".to_string());

    let config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..empty_config()
    };
    let json = serde_json::to_string(&config).expect("serialize config");
    let mut decoded: GatewayConfig = serde_json::from_str(&json).expect("deserialize config");
    assert_eq!(
        decoded.proxies[0].resolved_tls.sni, None,
        "resolved_tls is skipped on the wire and must be rebuilt"
    );

    decoded.normalize_fields();

    let resolved = &decoded.proxies[0].resolved_tls;
    assert_eq!(resolved.sni.as_deref(), Some("reviews.mesh.internal"));
    assert_eq!(resolved.san_allow_list, vec!["reviews.mesh.internal"]);
    assert_eq!(
        decoded.upstreams[0].backend_tls_sni.as_deref(),
        Some("reviews.mesh.internal")
    );
}

#[test]
fn normalize_fields_recomputes_per_port_tls_san_digests_after_serde_round_trip() {
    let mut upstream = make_upstream("reviews-u");
    upstream.port_overrides.insert(
        8443,
        UpstreamPortOverride {
            tls: Some(BackendTlsConfig {
                sni: Some("Reviews.Mesh.Internal".to_string()),
                san_allow_list: vec!["Reviews.Mesh.Internal".to_string()],
                ..BackendTlsConfig::default_verify()
            }),
            ..UpstreamPortOverride::default()
        },
    );
    upstream.port_overrides.insert(
        9443,
        UpstreamPortOverride {
            tls: Some(BackendTlsConfig {
                sni: Some("Ratings.Mesh.Internal".to_string()),
                san_allow_list: vec!["Ratings.Mesh.Internal".to_string()],
                ..BackendTlsConfig::default_verify()
            }),
            ..UpstreamPortOverride::default()
        },
    );

    let mut proxy = make_proxy("reviews-p", "/reviews");
    proxy.upstream_id = Some("reviews-u".to_string());

    let config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..empty_config()
    };
    let json = serde_json::to_string(&config).expect("serialize config");
    let mut decoded: GatewayConfig = serde_json::from_str(&json).expect("deserialize config");
    assert!(
        decoded.upstreams[0]
            .port_overrides
            .values()
            .all(|override_config| override_config
                .tls
                .as_ref()
                .is_some_and(|tls| tls.san_allow_list_key_digest.is_none())),
        "per-port TLS SAN digests are skipped on the wire and must be rebuilt"
    );

    decoded.normalize_fields();

    let dispatch_overrides = decoded.proxies[0]
        .dispatch_port_overrides
        .as_ref()
        .expect("dispatch port overrides projected");
    let reviews_tls = dispatch_overrides
        .get(&8443)
        .and_then(|override_config| override_config.tls.as_ref())
        .expect("reviews per-port TLS projected");
    let ratings_tls = dispatch_overrides
        .get(&9443)
        .and_then(|override_config| override_config.tls.as_ref())
        .expect("ratings per-port TLS projected");

    assert_eq!(reviews_tls.sni.as_deref(), Some("reviews.mesh.internal"));
    assert_eq!(reviews_tls.san_allow_list, vec!["reviews.mesh.internal"]);
    assert!(reviews_tls.san_allow_list_key_digest.is_some());
    assert!(ratings_tls.san_allow_list_key_digest.is_some());
    assert_ne!(
        reviews_tls.san_allow_list_key_digest, ratings_tls.san_allow_list_key_digest,
        "distinct per-port SAN policies must fragment backend pool keys"
    );
}

#[test]
fn normalize_fields_rebuilds_direct_proxy_resolved_tls_after_mutation() {
    let mut proxy = make_proxy("direct-p", "/direct");
    proxy.backend_tls_client_cert_path = Some("/certs/client.pem".to_string());
    proxy.backend_tls_client_key_path = Some("/certs/client-key.pem".to_string());
    proxy.backend_tls_server_ca_cert_path = Some("/certs/ca.pem".to_string());
    proxy.backend_tls_verify_server_cert = false;

    let mut config = GatewayConfig {
        proxies: vec![proxy],
        ..empty_config()
    };
    config.normalize_fields();

    let resolved = &config.proxies[0].resolved_tls;
    assert_eq!(
        resolved.client_cert_path.as_deref(),
        Some("/certs/client.pem")
    );
    assert_eq!(
        resolved.client_key_path.as_deref(),
        Some("/certs/client-key.pem")
    );
    assert_eq!(
        resolved.server_ca_cert_path.as_deref(),
        Some("/certs/ca.pem")
    );
    assert!(!resolved.verify_server_cert);
}

#[test]
fn normalize_fields_reprojects_resolved_tls_after_upstream_mutation() {
    let mut upstream = make_upstream("reviews-u");
    upstream.backend_tls_sni = Some("old.mesh.internal".to_string());
    let mut proxy = make_proxy("reviews-p", "/reviews");
    proxy.upstream_id = Some("reviews-u".to_string());

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..empty_config()
    };
    config.normalize_fields();
    assert_eq!(
        config.proxies[0].resolved_tls.sni.as_deref(),
        Some("old.mesh.internal")
    );

    config.upstreams[0].backend_tls_sni = Some("New.Mesh.Internal".to_string());
    config.proxies[0].resolved_tls.sni = Some("stale.mesh.internal".to_string());
    config.normalize_fields();

    assert_eq!(
        config.proxies[0].resolved_tls.sni.as_deref(),
        Some("new.mesh.internal")
    );
}

#[test]
fn resolve_upstream_tls_refreshes_proxy_cache_after_upstream_mutation() {
    let mut upstream = make_upstream("reviews-u");
    upstream.backend_tls_server_ca_cert_path = Some("/mesh/ca-a.pem".to_string());
    upstream.backend_tls_sni = Some("reviews-a.mesh.internal".to_string());
    upstream.backend_tls_san_allow_list = vec!["reviews-a.mesh.internal".to_string()];
    upstream.backend_tls_verify_server_cert = false;

    let mut proxy = make_proxy("reviews-p", "/reviews");
    proxy.upstream_id = Some("reviews-u".to_string());

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..empty_config()
    };
    config.resolve_upstream_tls();

    assert_eq!(
        config.proxies[0]
            .resolved_tls
            .server_ca_cert_path
            .as_deref(),
        Some("/mesh/ca-a.pem")
    );
    assert_eq!(
        config.proxies[0].resolved_tls.sni.as_deref(),
        Some("reviews-a.mesh.internal")
    );
    assert!(!config.proxies[0].resolved_tls.verify_server_cert);
    let first_digest = config.proxies[0]
        .resolved_tls
        .san_allow_list_key_digest
        .clone();

    config.upstreams[0].backend_tls_server_ca_cert_path = Some("/mesh/ca-b.pem".to_string());
    config.upstreams[0].backend_tls_sni = Some("reviews-b.mesh.internal".to_string());
    config.upstreams[0].backend_tls_san_allow_list = vec!["reviews-b.mesh.internal".to_string()];
    config.upstreams[0].backend_tls_verify_server_cert = true;
    config.resolve_upstream_tls();

    let resolved = &config.proxies[0].resolved_tls;
    assert_eq!(
        resolved.server_ca_cert_path.as_deref(),
        Some("/mesh/ca-b.pem")
    );
    assert_eq!(resolved.sni.as_deref(), Some("reviews-b.mesh.internal"));
    assert!(resolved.verify_server_cert);
    assert_ne!(
        resolved.san_allow_list_key_digest, first_digest,
        "SAN digest must be recomputed when upstream SAN policy changes"
    );
}

#[test]
fn resolve_upstream_tls_switches_upstream_proxy_back_to_direct_tls() {
    let mut upstream = make_upstream("reviews-u");
    upstream.backend_tls_server_ca_cert_path = Some("/mesh/upstream-ca.pem".to_string());

    let mut proxy = make_proxy("reviews-p", "/reviews");
    proxy.upstream_id = Some("reviews-u".to_string());
    proxy.backend_tls_server_ca_cert_path = Some("/direct/proxy-ca.pem".to_string());
    proxy.backend_tls_verify_server_cert = false;

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![proxy],
        ..empty_config()
    };
    config.resolve_upstream_tls();

    assert_eq!(
        config.proxies[0]
            .resolved_tls
            .server_ca_cert_path
            .as_deref(),
        Some("/mesh/upstream-ca.pem")
    );
    assert!(config.proxies[0].resolved_tls.verify_server_cert);

    config.proxies[0].upstream_id = None;
    config.resolve_upstream_tls();

    let resolved = &config.proxies[0].resolved_tls;
    assert_eq!(
        resolved.server_ca_cert_path.as_deref(),
        Some("/direct/proxy-ca.pem")
    );
    assert!(!resolved.verify_server_cert);
    assert!(
        resolved.sni.is_none() && resolved.san_allow_list.is_empty(),
        "direct proxy TLS projection must clear upstream-only SNI/SAN cache state"
    );
}

#[test]
fn resolve_upstream_tls_falls_back_when_subset_overlay_is_empty_or_missing() {
    let mut upstream = make_upstream("reviews-u");
    upstream.backend_tls_server_ca_cert_path = Some("/mesh/upstream-ca.pem".to_string());
    upstream
        .resolved_subset_tls
        .insert("empty".to_string(), ResolvedSubsetTrafficPolicy::default());
    upstream.resolved_subset_tls.insert(
        "canary".to_string(),
        ResolvedSubsetTrafficPolicy {
            tls: Some(BackendTlsConfig {
                server_ca_cert_path: Some("/mesh/canary-ca.pem".to_string()),
                sni: Some("canary.mesh.internal".to_string()),
                san_allow_list: vec!["canary.mesh.internal".to_string()],
                ..BackendTlsConfig::default_verify()
            }),
            passive_health_check: None,
        },
    );
    upstream
        .resolved_subset_tls
        .get_mut("canary")
        .and_then(|resolved| resolved.tls.as_mut())
        .expect("canary tls")
        .recompute_san_digest();

    let mut empty = make_proxy("empty-p", "/empty");
    empty.upstream_id = Some("reviews-u".to_string());
    empty.upstream_subset = Some("empty".to_string());
    let mut missing = make_proxy("missing-p", "/missing");
    missing.upstream_id = Some("reviews-u".to_string());
    missing.upstream_subset = Some("missing".to_string());
    let mut canary = make_proxy("canary-p", "/canary");
    canary.upstream_id = Some("reviews-u".to_string());
    canary.upstream_subset = Some("canary".to_string());

    let mut config = GatewayConfig {
        upstreams: vec![upstream],
        proxies: vec![empty, missing, canary],
        ..empty_config()
    };
    config.resolve_upstream_tls();

    assert_eq!(
        config.proxies[0]
            .resolved_tls
            .server_ca_cert_path
            .as_deref(),
        Some("/mesh/upstream-ca.pem"),
        "empty subset TLS overlay should fall back to upstream-level TLS"
    );
    assert_eq!(
        config.proxies[1]
            .resolved_tls
            .server_ca_cert_path
            .as_deref(),
        Some("/mesh/upstream-ca.pem"),
        "missing subset TLS overlay should fall back to upstream-level TLS"
    );
    assert_eq!(
        config.proxies[2]
            .resolved_tls
            .server_ca_cert_path
            .as_deref(),
        Some("/mesh/canary-ca.pem"),
        "non-empty subset TLS overlay should replace upstream-level TLS"
    );
    assert_eq!(
        config.proxies[2].resolved_tls.sni.as_deref(),
        Some("canary.mesh.internal")
    );
}

#[test]
fn backend_tls_san_digest_ignores_order_and_duplicate_entries() {
    let mut with_duplicates = make_upstream("dupes");
    with_duplicates.backend_tls_san_allow_list = vec![
        "reviews.mesh.internal".to_string(),
        "ratings.mesh.internal".to_string(),
        "reviews.mesh.internal".to_string(),
    ];

    let mut canonical = make_upstream("canonical");
    canonical.backend_tls_san_allow_list = vec![
        "ratings.mesh.internal".to_string(),
        "reviews.mesh.internal".to_string(),
    ];

    let with_duplicates = BackendTlsConfig::from_upstream(&with_duplicates);
    let canonical = BackendTlsConfig::from_upstream(&canonical);

    assert_eq!(
        with_duplicates.san_allow_list_key_digest, canonical.san_allow_list_key_digest,
        "duplicate SAN entries should not fragment equivalent backend TLS identities"
    );
}

#[test]
fn upstream_normalize_fields_lowercases_backend_tls_sni() {
    let mut upstream = make_upstream("tls-upstream");
    upstream.backend_tls_sni = Some("Reviews.Mesh.Internal".to_string());

    upstream.normalize_fields();

    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("reviews.mesh.internal")
    );
}

#[test]
fn upstream_normalize_fields_lowercases_dns_sans_only() {
    let mut upstream = make_upstream("tls-upstream");
    upstream.backend_tls_san_allow_list = vec![
        "Reviews.Mesh.Internal".to_string(),
        "spiffe://Cluster.Local/ns/Default/sa/Reviews".to_string(),
        "10.0.0.8".to_string(),
        "2001:db8::1".to_string(),
    ];

    upstream.normalize_fields();

    assert_eq!(
        upstream.backend_tls_san_allow_list,
        vec![
            "reviews.mesh.internal".to_string(),
            "spiffe://Cluster.Local/ns/Default/sa/Reviews".to_string(),
            "10.0.0.8".to_string(),
            "2001:db8::1".to_string(),
        ]
    );
}

/// Helper to create an empty gateway config.
fn empty_config() -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn mtls_plugin(
    id: &str,
    scope: PluginScope,
    proxy_id: Option<&str>,
    config: serde_json::Value,
) -> PluginConfig {
    PluginConfig {
        id: id.to_string(),
        plugin_name: "mtls_auth".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config,
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn stream_proxy(id: &str, scheme: BackendScheme, frontend_tls: bool) -> Proxy {
    let mut proxy = make_proxy(id, "/unused");
    proxy.listen_path = None;
    proxy.backend_scheme = Some(scheme);
    proxy.dispatch_kind = DispatchKind::from(scheme);
    proxy.listen_port = Some(if scheme.is_udp() { 5353 } else { 5432 });
    proxy.frontend_tls = frontend_tls;
    proxy
}

#[test]
fn mtls_auth_compatibility_rejects_plaintext_and_passthrough_streams() {
    let plaintext = stream_proxy("plain", BackendScheme::Tcp, false);
    let mut passthrough = stream_proxy("passthrough", BackendScheme::Tcp, false);
    passthrough.passthrough = true;
    let config = GatewayConfig {
        proxies: vec![plaintext, passthrough],
        plugin_configs: vec![mtls_plugin(
            "mtls-global",
            PluginScope::Global,
            None,
            serde_json::json!({}),
        )],
        ..empty_config()
    };

    let errors = config.validate_mtls_auth_compatibility().unwrap_err();
    assert_eq!(errors.len(), 2);
    assert!(errors.iter().any(|error| error.contains("Proxy 'plain'")));
    assert!(
        errors
            .iter()
            .any(|error| error.contains("passthrough=false"))
    );
}

#[test]
fn mtls_auth_compatibility_checks_proxy_and_proxy_group_scopes() {
    let mut proxy = stream_proxy("tcp", BackendScheme::Tcp, false);
    proxy.plugins = vec![
        PluginAssociation {
            plugin_config_id: "mtls-proxy".to_string(),
        },
        PluginAssociation {
            plugin_config_id: "mtls-group".to_string(),
        },
    ];
    let config = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![
            mtls_plugin(
                "mtls-proxy",
                PluginScope::Proxy,
                Some("tcp"),
                serde_json::json!({}),
            ),
            mtls_plugin(
                "mtls-group",
                PluginScope::ProxyGroup,
                None,
                serde_json::json!({}),
            ),
        ],
        ..empty_config()
    };

    let errors = config.validate_mtls_auth_compatibility().unwrap_err();
    assert_eq!(errors.len(), 2);
    assert!(errors.iter().any(|error| error.contains("mtls-proxy")));
    assert!(errors.iter().any(|error| error.contains("mtls-group")));
}

#[test]
fn mtls_auth_compatibility_rejects_chain_fingerprints_on_dtls() {
    let config = GatewayConfig {
        proxies: vec![stream_proxy("dtls", BackendScheme::Dtls, true)],
        plugin_configs: vec![mtls_plugin(
            "mtls-global",
            PluginScope::Global,
            None,
            serde_json::json!({
                "allowed_ca_fingerprints_sha256": ["00".repeat(32)]
            }),
        )],
        ..empty_config()
    };

    let errors = config.validate_mtls_auth_compatibility().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("UDP/DTLS does not expose"));
}

#[test]
fn mtls_auth_compatibility_allows_terminated_tcp_and_dtls_issuer_pins() {
    let config = GatewayConfig {
        proxies: vec![
            stream_proxy("tcp", BackendScheme::Tcp, true),
            stream_proxy("dtls", BackendScheme::Dtls, true),
        ],
        plugin_configs: vec![mtls_plugin(
            "mtls-global",
            PluginScope::Global,
            None,
            serde_json::json!({
                "allowed_issuers": [{
                    "cn": "Internal CA",
                    "ca_certificate_pem": "configured CA PEM"
                }]
            }),
        )],
        ..empty_config()
    };

    assert!(config.validate_mtls_auth_compatibility().is_ok());
}

#[test]
fn local_mtls_auth_shadows_incompatible_global_fingerprint_policy() {
    let mut proxy = stream_proxy("dtls", BackendScheme::Dtls, true);
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "mtls-local".to_string(),
    }];
    let config = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![
            mtls_plugin(
                "mtls-global",
                PluginScope::Global,
                None,
                serde_json::json!({
                    "allowed_ca_fingerprints_sha256": ["00".repeat(32)]
                }),
            ),
            mtls_plugin(
                "mtls-local",
                PluginScope::Proxy,
                Some("dtls"),
                serde_json::json!({}),
            ),
        ],
        ..empty_config()
    };

    assert!(config.validate_mtls_auth_compatibility().is_ok());

    let mut removed = config.clone();
    removed
        .plugin_configs
        .retain(|plugin| plugin.id != "mtls-local");
    let removal_errors = removed.validate_mtls_auth_compatibility().unwrap_err();
    assert!(
        removal_errors
            .iter()
            .any(|error| error.contains("UDP/DTLS does not expose"))
    );

    let mut renamed = config;
    renamed
        .plugin_configs
        .iter_mut()
        .find(|plugin| plugin.id == "mtls-local")
        .expect("local plugin exists")
        .plugin_name = "cors".to_string();
    let rename_errors = renamed.validate_mtls_auth_compatibility().unwrap_err();
    assert!(
        rename_errors
            .iter()
            .any(|error| error.contains("UDP/DTLS does not expose"))
    );
}

#[test]
fn frontend_tls_mtls_example_is_a_valid_gateway_config() {
    let docs = include_str!("../../../docs/frontend_tls.md");
    let section = docs
        .split("### Per-Proxy CA Filtering with `mtls_auth`")
        .nth(1)
        .expect("mTLS filtering section exists");
    let yaml = section
        .split("```yaml")
        .nth(1)
        .and_then(|tail| tail.split("```").next())
        .expect("mTLS filtering section contains a YAML example");
    let mut config: GatewayConfig = serde_yaml::from_str(yaml).expect("example YAML parses");

    assert!(config.validate_all_fields(30).is_ok());
    config.normalize_fields();
    assert!(config.validate_plugin_references().is_ok());
    for plugin_config in &config.plugin_configs {
        assert!(
            ferrum_edge::plugins::create_plugin(&plugin_config.plugin_name, &plugin_config.config,)
                .is_ok(),
            "documented PluginConfig '{}' must construct",
            plugin_config.id
        );
    }
}

#[test]
fn test_unique_listen_paths_valid() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                id: "1".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: Some("/api/v1".to_string()),
                backend_scheme: Some(BackendScheme::Http),
                dispatch_kind: DispatchKind::from(BackendScheme::Http),
                backend_host: "localhost".into(),
                backend_port: 3000,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: AuthMode::Single,
                plugins: vec![],

                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Proxy {
                id: "2".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: Some("/api/v2".to_string()),
                backend_scheme: Some(BackendScheme::Http),
                dispatch_kind: DispatchKind::from(BackendScheme::Http),
                backend_host: "localhost".into(),
                backend_port: 3001,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: AuthMode::Single,
                plugins: vec![],

                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    assert!(config.validate_unique_listen_paths().is_ok());
}

#[test]
fn test_unique_listen_paths_duplicate() {
    let config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![
            Proxy {
                id: "1".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: Some("/api/v1".to_string()),
                backend_scheme: Some(BackendScheme::Http),
                dispatch_kind: DispatchKind::from(BackendScheme::Http),
                backend_host: "localhost".into(),
                backend_port: 3000,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: AuthMode::Single,
                plugins: vec![],

                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            Proxy {
                id: "2".into(),
                namespace: ferrum_edge::config::types::default_namespace(),
                name: None,
                hosts: vec![],
                listen_path: Some("/api/v1".to_string()),
                backend_scheme: Some(BackendScheme::Http),
                dispatch_kind: DispatchKind::from(BackendScheme::Http),
                backend_host: "localhost".into(),
                backend_port: 3001,
                backend_path: None,
                strip_listen_path: true,
                preserve_host_header: false,
                backend_connect_timeout_ms: 5000,
                backend_read_timeout_ms: 30000,
                backend_write_timeout_ms: 30000,
                backend_tls_client_cert_path: None,
                backend_tls_client_key_path: None,
                backend_tls_verify_server_cert: true,
                backend_tls_server_ca_cert_path: None,
                resolved_tls: Default::default(),
                dispatch_port_overrides: None,
                dispatch_port_override_fallback: None,
                dns_override: None,
                dns_cache_ttl_seconds: None,
                auth_mode: AuthMode::Single,
                plugins: vec![],

                pool_idle_timeout_seconds: Some(30),
                pool_enable_http_keep_alive: Some(true),
                pool_enable_http2: Some(true),
                pool_http2_keep_alive_interval_seconds: Some(15),
                pool_http2_keep_alive_timeout_seconds: Some(5),
                pool_http2_initial_stream_window_size: None,
                pool_http2_initial_connection_window_size: None,
                pool_http2_adaptive_window: None,
                pool_http2_max_frame_size: None,
                pool_http2_max_concurrent_streams: None,
                pool_http3_connections_per_backend: None,
                h2_upgrade_policy: None,
                pool_max_requests_per_connection: None,
                pool_http1_max_pending_requests: None,
                pool_tcp_keepalive_seconds: Some(10),
                upstream_id: None,
                upstream_subset: None,
                api_spec_id: None,
                circuit_breaker: None,
                retry: None,
                response_body_mode: Default::default(),
                listen_port: None,
                frontend_tls: false,
                passthrough: false,
                udp_idle_timeout_seconds: 60,
                tcp_idle_timeout_seconds: Some(300),
                websocket_idle_timeout_seconds: None,
                allowed_methods: None,
                allowed_ws_origins: vec![],
                udp_max_response_amplification_factor: None,
                stream_proxy_protocol: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        ],
        consumers: vec![],
        plugin_configs: vec![],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    assert!(config.validate_unique_listen_paths().is_err());
}

// ---- Consumer credential uniqueness tests ----

#[test]
fn test_unique_consumer_credentials_valid() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "key-aaa"}]));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "key-bbb"}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_unique_consumer_credentials_duplicate_keyauth() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "same-key"}]));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "same-key"}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate keyauth API key"));
    // Verify the API key value is NOT in the error message (security)
    assert!(!err[0].contains("same-key"));
}

#[test]
fn test_unique_consumer_credentials_duplicate_hmac_secret_is_redacted() {
    let secret = "same-hmac-secret-at-least-32-characters";
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    let errors = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("Duplicate hmac_auth shared secret"));
    assert!(!errors[0].contains(secret));
}

#[test]
fn test_unique_consumer_credentials_allows_hmac_rotation_within_one_consumer() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([
            {"secret": "first-hmac-secret-at-least-32-characters"},
            {"secret": "second-hmac-secret-at-least-32-characters"}
        ]),
    );
    let mut config = empty_config();
    config.consumers = vec![consumer];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_validate_unique_hmac_credentials_narrow_surface() {
    let secret = "same-hmac-secret-at-least-32-characters";
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    // Unrelated keyauth collision must NOT surface through the narrow check.
    c1.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "same-key"}]));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    c2.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "same-key"}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    let errors = config.validate_unique_hmac_credentials().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("Duplicate hmac_auth shared secret"));
    assert!(!errors[0].contains(secret));

    config.consumers[1].credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([{"secret": "distinct-hmac-secret-at-least-32-chars!"}]),
    );
    assert!(config.validate_unique_hmac_credentials().is_ok());
}

#[test]
fn test_hmac_secret_uniqueness_and_quarantine_are_namespace_scoped() {
    let secret = "namespace-reusable-hmac-secret-at-least-32-characters";
    let mut tenant_a = make_consumer("shared-id", "alice");
    tenant_a.namespace = "tenant-a".to_string();
    tenant_a
        .credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    let mut tenant_b = make_consumer("shared-id", "bob");
    tenant_b.namespace = "tenant-b".to_string();
    tenant_b
        .credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    let mut config = empty_config();
    config.consumers = vec![tenant_a, tenant_b];

    assert!(config.validate_unique_hmac_credentials().is_ok());
    assert!(config.validate_unique_consumer_credentials().is_ok());
    assert!(config.quarantine_invalid_hmac_credentials().is_empty());
    assert!(
        config
            .consumers
            .iter()
            .all(|consumer| consumer.has_credential("hmac_auth"))
    );
}

#[test]
fn test_quarantine_hmac_strips_weak_secret_and_keeps_strong() {
    let weak = "short-secret";
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": weak}]));
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([{"secret": "strong-hmac-secret-at-least-32-characters"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    let messages = config.quarantine_invalid_hmac_credentials();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("consumer 'c1'"));
    assert!(!messages[0].contains(weak));
    assert!(!config.consumers[0].has_credential("hmac_auth"));
    assert!(config.consumers[1].has_credential("hmac_auth"));
}

#[test]
fn test_quarantine_hmac_strips_credential_when_any_rotation_entry_is_weak() {
    // A single weak rotation entry disables the whole credential — fail
    // closed rather than letting the weak entry authenticate.
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([
            {"secret": "strong-hmac-secret-at-least-32-characters"},
            {"secret": "weak"}
        ]),
    );
    let mut config = empty_config();
    config.consumers = vec![consumer];

    let messages = config.quarantine_invalid_hmac_credentials();
    assert_eq!(messages.len(), 1);
    assert!(!config.consumers[0].has_credential("hmac_auth"));
}

#[test]
fn test_quarantine_hmac_strips_malformed_credentials() {
    // Whitespace padding must not count toward the strength minimum.
    let padded = format!("{}short{}", " ".repeat(20), " ".repeat(20));
    let shapes = [
        serde_json::json!([{"secret": 12345}]),
        serde_json::json!([]),
        serde_json::json!({"secret": "not-an-array-secret-at-least-32-chars!"}),
        serde_json::json!([{"no_secret": true}]),
        serde_json::json!([{
            "secret": "strong-hmac-secret-at-least-32-characters",
            "unexpected": true
        }]),
        serde_json::json!([{"secret": padded}]),
    ];
    for shape in shapes {
        let mut consumer = make_consumer("c1", "alice");
        consumer
            .credentials
            .insert("hmac_auth".into(), shape.clone());
        let mut config = empty_config();
        config.consumers = vec![consumer];

        let messages = config.quarantine_invalid_hmac_credentials();
        assert_eq!(messages.len(), 1, "shape not quarantined: {shape}");
        assert!(!config.consumers[0].credentials.contains_key("hmac_auth"));
    }
}

#[test]
fn test_quarantine_hmac_duplicate_secret_first_loaded_consumer_wins() {
    let secret = "same-hmac-secret-at-least-32-characters";
    let mut c1 = make_consumer("c1", "alice");
    // Intra-consumer rotation reuse of one secret is allowed.
    c1.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([{"secret": secret}, {"secret": secret}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("hmac_auth".into(), serde_json::json!([{"secret": secret}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    let messages = config.quarantine_invalid_hmac_credentials();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("consumer 'c2'"));
    assert!(messages[0].contains("consumer 'c1'"));
    assert!(!messages[0].contains(secret));
    assert!(config.consumers[0].has_credential("hmac_auth"));
    assert!(!config.consumers[1].has_credential("hmac_auth"));
}

#[test]
fn test_unique_consumer_credentials_no_keyauth_ok() {
    // Consumers without keyauth credentials should not conflict
    let c1 = make_consumer("c1", "alice");
    let c2 = make_consumer("c2", "bob");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_unique_consumer_credentials_duplicate_basicauth() {
    // Two consumers with basicauth and the same username should conflict
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:abc"}]),
    );
    let mut c2 = make_consumer("c2", "alice");
    c2.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:def"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate basicauth username"));
}

#[test]
fn test_unique_consumer_credentials_basicauth_different_usernames_ok() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:abc"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:def"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_unique_consumer_credentials_duplicate_mtls_identity() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=client1"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=client1"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate mtls_auth identity"));
}

#[test]
fn test_unique_consumer_credentials_mtls_different_identities_ok() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=client1"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=client2"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_unique_mtls_credentials_ignore_unrelated_credential_collisions() {
    let mut c1 = make_consumer("c1", "shared-user");
    c1.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "legacy-duplicate"}]),
    );
    c1.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:first"}]),
    );
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "client-a.example.com"}]),
    );
    let mut c2 = make_consumer("c2", "shared-user");
    c2.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "legacy-duplicate"}]),
    );
    c2.credentials.insert(
        "basicauth".into(),
        serde_json::json!([{"password_hash": "hmac_sha256:second"}]),
    );
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "client-b.example.com"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    assert!(config.validate_unique_consumer_credentials().is_err());
    assert!(config.validate_unique_mtls_credentials().is_ok());
}

#[test]
fn test_unique_consumer_credentials_scopes_case_folding_to_san_dns() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "API.Example.COM"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "api.example.com"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    config.proxies.push(make_proxy("p1", "/"));

    assert!(
        config.validate_unique_consumer_credentials().is_ok(),
        "exact-match certificate fields must permit case-variant identities"
    );

    let mut dns_plugin = mtls_plugin(
        "dns-mtls",
        PluginScope::Global,
        None,
        serde_json::json!({"cert_field": "san_dns"}),
    );
    dns_plugin.enabled = false;
    config.plugin_configs.push(dns_plugin);
    assert!(
        config.validate_unique_consumer_credentials().is_ok(),
        "a disabled san_dns policy must not constrain exact-match deployments"
    );
    config.plugin_configs[0].enabled = true;

    let errors = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("ASCII case-insensitive"));
}

#[test]
fn test_unique_mtls_dns_identities_include_global_fallback_without_proxies() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "API.Example.COM"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "api.example.com"}]),
    );
    let config = GatewayConfig {
        consumers: vec![c1, c2],
        plugin_configs: vec![mtls_plugin(
            "global-dns-mtls",
            PluginScope::Global,
            None,
            serde_json::json!({"cert_field": "san_dns"}),
        )],
        ..empty_config()
    };

    let errors = config.validate_unique_mtls_credentials().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("ASCII case-insensitive"));
}

#[test]
fn test_unique_mtls_dns_identities_ignore_unattached_plugin() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "API.Example.COM"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "api.example.com"}]),
    );
    let mut proxy = make_proxy("p1", "/");
    let dns_plugin = mtls_plugin(
        "dns-mtls",
        PluginScope::Proxy,
        Some("p1"),
        serde_json::json!({"cert_field": "san_dns"}),
    );
    let mut config = GatewayConfig {
        proxies: vec![proxy.clone()],
        consumers: vec![c1, c2],
        plugin_configs: vec![dns_plugin],
        ..empty_config()
    };

    assert!(config.validate_unique_mtls_credentials().is_ok());

    proxy.plugins.push(PluginAssociation {
        plugin_config_id: "dns-mtls".to_string(),
    });
    config.proxies[0] = proxy;
    assert!(config.validate_unique_mtls_credentials().is_err());
}

#[test]
fn test_unique_mtls_dns_identities_include_global_fallback_when_all_proxies_shadow_it() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "Api.EXAMPLE.com"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "api.example.com"}]),
    );
    let mut proxy1 = make_proxy("p1", "/one");
    proxy1.plugins.push(PluginAssociation {
        plugin_config_id: "local-exact-mtls-p1".to_string(),
    });
    let mut proxy2 = make_proxy("p2", "/two");
    proxy2.plugins.push(PluginAssociation {
        plugin_config_id: "local-exact-mtls-p2".to_string(),
    });
    let config = GatewayConfig {
        proxies: vec![proxy1, proxy2],
        consumers: vec![c1, c2],
        plugin_configs: vec![
            mtls_plugin(
                "global-dns-mtls",
                PluginScope::Global,
                None,
                serde_json::json!({"cert_field": "san_dns"}),
            ),
            mtls_plugin(
                "local-exact-mtls-p1",
                PluginScope::Proxy,
                Some("p1"),
                serde_json::json!({"cert_field": "subject_cn"}),
            ),
            mtls_plugin(
                "local-exact-mtls-p2",
                PluginScope::Proxy,
                Some("p2"),
                serde_json::json!({"cert_field": "subject_cn"}),
            ),
        ],
        ..empty_config()
    };

    let errors = config.validate_unique_mtls_credentials().unwrap_err();
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("ASCII case-insensitive"));
}

// ---- Multi-credential (array format) tests ----

#[test]
fn test_credential_entries_object_value_is_ignored() {
    let mut c = make_consumer("c1", "alice");
    c.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "abc"}));
    let entries = c.credential_entries("keyauth");
    assert!(entries.is_empty());
}

#[test]
fn test_credential_entries_array() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "abc"}, {"key": "def"}]),
    );
    let entries = c.credential_entries("keyauth");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].get("key").unwrap().as_str().unwrap(), "abc");
    assert_eq!(entries[1].get("key").unwrap().as_str().unwrap(), "def");
}

#[test]
fn test_credential_entries_empty() {
    let c = make_consumer("c1", "alice");
    let entries = c.credential_entries("keyauth");
    assert!(entries.is_empty());
}

#[test]
fn test_credential_entries_filters_non_objects_in_array() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "abc"}, "not-an-object", 42]),
    );
    let entries = c.credential_entries("keyauth");
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_has_credential_object_value_is_false() {
    let mut c = make_consumer("c1", "alice");
    c.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "abc"}));
    assert!(!c.has_credential("keyauth"));
    assert!(!c.has_credential("jwt"));
}

#[test]
fn test_has_credential_array() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "abc"}, {"key": "def"}]),
    );
    assert!(c.has_credential("keyauth"));
}

#[test]
fn test_unique_credentials_array_duplicate_keyauth_across_consumers() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "key-aaa"}, {"key": "key-bbb"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "key-bbb"}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate keyauth API key"));
}

#[test]
fn test_unique_credentials_array_no_duplicate() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "key-aaa"}, {"key": "key-bbb"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials
        .insert("keyauth".into(), serde_json::json!([{"key": "key-ccc"}]));
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_credentials().is_ok());
}

#[test]
fn test_unique_credentials_array_duplicate_mtls_across_consumers() {
    let mut c1 = make_consumer("c1", "alice");
    c1.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=a"}, {"identity": "CN=b"}]),
    );
    let mut c2 = make_consumer("c2", "bob");
    c2.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "CN=b"}]),
    );
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_credentials().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate mtls_auth identity"));
}

#[test]
fn test_validate_fields_array_credentials_within_limit() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "keyauth".into(),
        serde_json::json!([{"key": "k1"}, {"key": "k2"}]),
    );
    assert!(c.validate_fields().is_ok());
}

#[test]
fn test_validate_fields_accepts_well_formed_mtls_credentials() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([
            {"identity": "client.example.com"},
            {"identity": "spiffe://example.test/ns/default/sa/alice"}
        ]),
    );
    assert!(consumer.validate_fields().is_ok());
}

#[test]
fn test_validate_fields_rejects_malformed_mtls_credentials() {
    for credential in [
        serde_json::json!({}),
        serde_json::json!({"identity": ""}),
        serde_json::json!({"identity": " \t "}),
        serde_json::json!({"identity": 42}),
        serde_json::json!({"identity": "client.example.com", "unexpected": true}),
        serde_json::json!({"subject": "client.example.com"}),
    ] {
        let mut consumer = make_consumer("c1", "alice");
        consumer
            .credentials
            .insert("mtls_auth".into(), serde_json::json!([credential]));
        assert!(
            consumer.validate_fields().is_err(),
            "malformed credential must fail closed: {:?}",
            consumer.credentials["mtls_auth"]
        );
    }
}

#[test]
fn test_normalize_fields_trims_mtls_identity_without_case_folding() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "mtls_auth".into(),
        serde_json::json!([{"identity": "  Client.Example.COM  "}]),
    );

    consumer.normalize_fields();

    assert_eq!(
        consumer.credentials["mtls_auth"][0]["identity"],
        "Client.Example.COM"
    );
}

#[test]
fn test_validate_fields_array_credentials_exceeds_max_per_type() {
    let mut c = make_consumer("c1", "alice");
    let entries: Vec<serde_json::Value> = (0..10)
        .map(|i| serde_json::json!({"key": format!("key-{}", i)}))
        .collect();
    c.credentials
        .insert("keyauth".into(), serde_json::Value::Array(entries));
    let err = c.validate_fields().unwrap_err();
    assert!(err.iter().any(|e| e.contains("must not exceed")));
}

#[test]
fn test_validate_fields_array_rejects_non_object_elements() {
    let mut c = make_consumer("c1", "alice");
    // Array of strings instead of objects — should be rejected
    c.credentials.insert(
        "keyauth".into(),
        serde_json::json!(["rotated-key", "another-key"]),
    );
    let err = c.validate_fields().unwrap_err();
    assert!(err.iter().any(|e| e.contains("must be a JSON object")));
}

#[test]
fn test_validate_fields_array_rejects_empty_array() {
    let mut c = make_consumer("c1", "alice");
    c.credentials
        .insert("keyauth".into(), serde_json::json!([]));
    let err = c.validate_fields().unwrap_err();
    assert!(err.iter().any(|e| e.contains("must not be empty")));
}

#[test]
fn test_validate_fields_rejects_non_object_credential_value() {
    let mut c = make_consumer("c1", "alice");
    // Plain string instead of array
    c.credentials
        .insert("keyauth".into(), serde_json::json!("just-a-string"));
    let err = c.validate_fields().unwrap_err();
    assert!(
        err.iter()
            .any(|e| e.contains("must be an array of JSON objects"))
    );
}

#[test]
fn test_validate_fields_rejects_single_object_credential_value() {
    let mut c = make_consumer("c1", "alice");
    c.credentials
        .insert("keyauth".into(), serde_json::json!({"key": "abc"}));
    let err = c.validate_fields().unwrap_err();
    assert!(
        err.iter()
            .any(|e| e.contains("must be an array of JSON objects"))
    );
}

#[test]
fn test_validate_fields_rejects_short_jwt_secret() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "short-secret"}]),
    );
    let err = c.validate_fields().unwrap_err();
    assert!(
        err.iter()
            .any(|e| e.contains("must be at least 32 characters"))
    );
}

#[test]
fn test_validate_fields_accepts_valid_jwt_secret() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "this-is-a-valid-jwt-secret-key-32chars"}]),
    );
    assert!(c.validate_fields().is_ok());
}

#[test]
fn test_validate_fields_rejects_unsupported_jwt_credential_shapes() {
    let valid_secret = "j".repeat(32);
    let oversized_secret = "j".repeat(ferrum_edge::config::types::MAX_CREDENTIAL_VALUE_LENGTH + 1);
    let control_secret = format!("{}{}", valid_secret, '\u{0001}');
    for credential in [
        serde_json::json!({}),
        serde_json::json!({"secret": null}),
        serde_json::json!({"secret": 42}),
        serde_json::json!({"secret": "🔐".repeat(31)}),
        serde_json::json!({"secret": oversized_secret}),
        serde_json::json!({"secret": control_secret}),
        serde_json::json!({"secret": valid_secret, "algorithm": "HS256"}),
        serde_json::json!({
            "secret": valid_secret,
            "algorithm": "RS256",
            "public_key": "pem"
        }),
        serde_json::json!({"secret": valid_secret, "jwks": {"keys": []}}),
        serde_json::json!({
            "secret": valid_secret,
            "jwks_uri": "https://issuer.example/jwks.json"
        }),
    ] {
        let mut consumer = make_consumer("c1", "alice");
        consumer
            .credentials
            .insert("jwt".into(), serde_json::json!([credential]));
        assert!(
            consumer.validate_fields().is_err(),
            "unsupported JWT credential must fail closed: {:?}",
            consumer.credentials["jwt"]
        );
    }
}

#[test]
fn test_validate_fields_accepts_jwt_character_boundaries_and_common_whitespace() {
    for secret in [
        "🔐".repeat(32),
        "j".repeat(ferrum_edge::config::types::MAX_CREDENTIAL_VALUE_LENGTH),
        format!("{}\t\n\r", "j".repeat(32)),
    ] {
        let mut consumer = make_consumer("c1", "alice");
        consumer
            .credentials
            .insert("jwt".into(), serde_json::json!([{"secret": secret}]));
        assert!(consumer.validate_fields().is_ok());
    }
}

#[test]
fn test_validate_fields_rejects_malformed_or_weak_hmac_secrets() {
    for credential in [
        serde_json::json!({}),
        serde_json::json!({"secret": null}),
        serde_json::json!({"secret": 42}),
        serde_json::json!({"secret": ""}),
        serde_json::json!({"secret": "                                "}),
        serde_json::json!({"secret": "short-secret"}),
        serde_json::json!({"secret": format!("{}{}", "h".repeat(31), " ".repeat(64))}),
        serde_json::json!({"secret": "valid-hmac-secret-at-least-32-characters", "extra": true}),
    ] {
        let mut consumer = make_consumer("c1", "alice");
        consumer
            .credentials
            .insert("hmac_auth".into(), serde_json::json!([credential]));
        assert!(
            consumer.validate_fields().is_err(),
            "malformed HMAC credential must fail closed: {:?}",
            consumer.credentials["hmac_auth"]
        );
    }
}

#[test]
fn test_validate_fields_accepts_strong_hmac_rotation_entries() {
    let mut consumer = make_consumer("c1", "alice");
    consumer.credentials.insert(
        "hmac_auth".into(),
        serde_json::json!([
            {"secret": "first-hmac-secret-at-least-32-characters"},
            {"secret": "second-hmac-secret-at-least-32-characters"}
        ]),
    );
    assert!(consumer.validate_fields().is_ok());
}

#[test]
fn test_validate_fields_credential_maxima_use_unicode_characters() {
    let max = ferrum_edge::config::types::MAX_CREDENTIAL_VALUE_LENGTH;
    for (cred_type, field) in [
        ("basicauth", "password"),
        ("keyauth", "key"),
        ("hmac_auth", "secret"),
        ("mtls_auth", "identity"),
    ] {
        let mut accepted = make_consumer("accepted", "alice");
        accepted.credentials.insert(
            cred_type.into(),
            serde_json::json!([{(field): "🔐".repeat(max)}]),
        );
        assert!(
            accepted.validate_fields().is_ok(),
            "{cred_type}.{field} must accept {max} multibyte characters"
        );

        let mut rejected = make_consumer("rejected", "bob");
        rejected.credentials.insert(
            cred_type.into(),
            serde_json::json!([{(field): "🔐".repeat(max + 1)}]),
        );
        let errors = rejected
            .validate_fields()
            .expect_err("4097 credential characters must be rejected");
        assert!(
            errors.iter().any(|error| error.contains(&format!(
                "credentials.{cred_type}[0].{field} must not exceed {max} characters (got {})",
                max + 1
            ))),
            "unexpected errors for {cred_type}.{field}: {errors:?}"
        );
    }
}

#[test]
fn test_validate_fields_rejects_short_jwt_secret_in_array() {
    let mut c = make_consumer("c1", "alice");
    c.credentials.insert(
        "jwt".into(),
        serde_json::json!([{"secret": "short"}, {"secret": "also-too-short-key"}]),
    );
    let err = c.validate_fields().unwrap_err();
    assert_eq!(
        err.iter()
            .filter(|e| e.contains("must be at least 32 characters"))
            .count(),
        2
    );
}

// ---- Consumer identity uniqueness tests ----

#[test]
fn test_unique_consumer_identities_valid() {
    let c1 = make_consumer("c1", "alice");
    let c2 = make_consumer("c2", "bob");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    assert!(config.validate_unique_consumer_identities().is_ok());
}

#[test]
fn test_unique_consumer_identities_duplicate_username() {
    let c1 = make_consumer("c1", "alice");
    let c2 = make_consumer("c2", "alice");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_identities().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate consumer username"));
}

#[test]
fn test_unique_consumer_identities_duplicate_custom_id() {
    let mut c1 = make_consumer("c1", "alice");
    c1.custom_id = Some("shared-id".into());
    let mut c2 = make_consumer("c2", "bob");
    c2.custom_id = Some("shared-id".into());
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_identities().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate consumer custom_id"));
}

#[test]
fn test_unique_consumer_identities_cross_namespace_collision() {
    // Consumer c2's custom_id collides with consumer c1's username
    let c1 = make_consumer("c1", "alice");
    let mut c2 = make_consumer("c2", "bob");
    c2.custom_id = Some("alice".into());
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_identities().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("collides with username"));
    assert!(err[0].contains("incorrect"));
}

#[test]
fn test_unique_consumer_identities_own_custom_id_matches_own_username() {
    // A consumer whose custom_id matches its own username should NOT be flagged
    let mut c1 = make_consumer("c1", "alice");
    c1.custom_id = Some("alice".into());
    let mut config = empty_config();
    config.consumers = vec![c1];
    assert!(config.validate_unique_consumer_identities().is_ok());
}

#[test]
fn test_unique_consumer_identities_username_collides_with_other_id() {
    let c1 = make_consumer("alice-id", "alice");
    let c2 = make_consumer("c2", "alice-id");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_identities().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("collides with id"));
}

#[test]
fn test_unique_consumer_identities_custom_id_collides_with_other_id() {
    let c1 = make_consumer("alice-id", "alice");
    let mut c2 = make_consumer("c2", "bob");
    c2.custom_id = Some("alice-id".into());
    let mut config = empty_config();
    config.consumers = vec![c1, c2];
    let err = config.validate_unique_consumer_identities().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("collides with id"));
}

#[test]
fn test_unique_consumer_identities_own_custom_id_matches_own_id() {
    let mut c1 = make_consumer("alice-id", "alice");
    c1.custom_id = Some("alice-id".into());
    let mut config = empty_config();
    config.consumers = vec![c1];
    assert!(config.validate_unique_consumer_identities().is_ok());
}

// ---- Consumer identity quarantine (issue #2121 fail-closed full load) ----

#[test]
fn test_quarantine_colliding_consumers_keeps_first_loaded() {
    // c2's custom_id collides with c1's username: c1 (loaded first) wins,
    // c2 is quarantined so ConsumerIndex never warn-and-overwrites.
    let c1 = make_consumer("c1", "alice");
    let mut c2 = make_consumer("c2", "bob");
    c2.custom_id = Some("alice".into());
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    let messages = config.quarantine_colliding_consumer_identities();

    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("Quarantined consumer 'c2'"));
    assert!(messages[0].contains("custom_id 'alice'"));
    assert_eq!(config.consumers.len(), 1);
    assert_eq!(config.consumers[0].id, "c1");
}

#[test]
fn test_quarantine_no_collisions_is_noop() {
    let c1 = make_consumer("c1", "alice");
    let c2 = make_consumer("c2", "bob");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    assert!(config.quarantine_colliding_consumer_identities().is_empty());
    assert_eq!(config.consumers.len(), 2);
}

#[test]
fn test_quarantine_allows_self_collision() {
    // A consumer whose own custom_id equals its own username/id is valid.
    let mut c1 = make_consumer("alice-id", "alice");
    c1.custom_id = Some("alice".into());
    let mut config = empty_config();
    config.consumers = vec![c1];

    assert!(config.quarantine_colliding_consumer_identities().is_empty());
    assert_eq!(config.consumers.len(), 1);
}

#[test]
fn test_quarantine_removed_consumer_does_not_claim_identities() {
    // c2 collides with c1 and is quarantined; c3 reuses c2's *other* identity
    // value — which must remain claimable because c2 was removed.
    let c1 = make_consumer("c1", "alice");
    let mut c2 = make_consumer("c2", "bob");
    c2.custom_id = Some("alice".into());
    let c3 = make_consumer("c3", "bob");
    let mut config = empty_config();
    config.consumers = vec![c1, c2, c3];

    let messages = config.quarantine_colliding_consumer_identities();

    assert_eq!(messages.len(), 1);
    assert_eq!(config.consumers.len(), 2);
    assert!(config.consumers.iter().any(|c| c.id == "c3"));
}

#[test]
fn test_quarantine_id_vs_username_collision() {
    let c1 = make_consumer("alice-id", "alice");
    let c2 = make_consumer("c2", "alice-id");
    let mut config = empty_config();
    config.consumers = vec![c1, c2];

    let messages = config.quarantine_colliding_consumer_identities();

    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("Quarantined consumer 'c2'"));
    assert_eq!(config.consumers.len(), 1);
}

// ---- Upstream name uniqueness tests ----

#[test]
fn test_unique_upstream_names_valid() {
    let mut u1 = make_upstream("u1");
    u1.name = Some("backend-api".into());
    let mut u2 = make_upstream("u2");
    u2.name = Some("backend-web".into());
    let mut config = empty_config();
    config.upstreams = vec![u1, u2];
    assert!(config.validate_unique_upstream_names().is_ok());
}

#[test]
fn test_unique_upstream_names_duplicate() {
    let mut u1 = make_upstream("u1");
    u1.name = Some("backend-api".into());
    let mut u2 = make_upstream("u2");
    u2.name = Some("backend-api".into());
    let mut config = empty_config();
    config.upstreams = vec![u1, u2];
    let err = config.validate_unique_upstream_names().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate upstream name 'backend-api'"));
}

#[test]
fn test_unique_upstream_names_none_allowed() {
    // Multiple upstreams with no name should be fine
    let u1 = make_upstream("u1");
    let u2 = make_upstream("u2");
    let mut config = empty_config();
    config.upstreams = vec![u1, u2];
    assert!(config.validate_unique_upstream_names().is_ok());
}

// ---- Proxy name uniqueness tests ----

#[test]
fn test_unique_proxy_names_valid() {
    let mut p1 = make_proxy("p1", "/api");
    p1.name = Some("api-proxy".into());
    let mut p2 = make_proxy("p2", "/web");
    p2.name = Some("web-proxy".into());
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    assert!(config.validate_unique_proxy_names().is_ok());
}

#[test]
fn test_unique_proxy_names_duplicate() {
    let mut p1 = make_proxy("p1", "/api");
    p1.name = Some("my-proxy".into());
    let mut p2 = make_proxy("p2", "/web");
    p2.name = Some("my-proxy".into());
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    let err = config.validate_unique_proxy_names().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate proxy name 'my-proxy'"));
}

#[test]
fn test_unique_proxy_names_none_allowed() {
    let p1 = make_proxy("p1", "/api");
    let p2 = make_proxy("p2", "/web");
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    assert!(config.validate_unique_proxy_names().is_ok());
}

// ---- Upstream reference validation tests ----

#[test]
fn test_upstream_references_valid() {
    let u1 = make_upstream("upstream-1");
    let mut p1 = make_proxy("p1", "/api");
    p1.upstream_id = Some("upstream-1".into());
    let mut config = empty_config();
    config.upstreams = vec![u1];
    config.proxies = vec![p1];
    assert!(config.validate_upstream_references().is_ok());
}

#[test]
fn test_upstream_references_missing() {
    let mut p1 = make_proxy("p1", "/api");
    p1.upstream_id = Some("nonexistent".into());
    let mut config = empty_config();
    config.proxies = vec![p1];
    let err = config.validate_upstream_references().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("non-existent upstream_id 'nonexistent'"));
}

#[test]
fn test_upstream_references_none_ok() {
    // Proxies without upstream_id should pass
    let p1 = make_proxy("p1", "/api");
    let mut config = empty_config();
    config.proxies = vec![p1];
    assert!(config.validate_upstream_references().is_ok());
}

#[test]
fn retry_proxy_rejects_required_mesh_transport_upstream_targets() {
    for tag in ["mesh.hbone", "mesh.mtls"] {
        let mut upstream = make_upstream("mesh-upstream");
        upstream.targets[0]
            .tags
            .insert(tag.to_string(), "true".to_string());
        let mut proxy = make_proxy("p1", "/api");
        proxy.upstream_id = Some("mesh-upstream".into());
        proxy.retry = Some(RetryConfig::default());
        let mut config = empty_config();
        config.upstreams = vec![upstream];
        config.proxies = vec![proxy];

        let err = config.validate_upstream_references().unwrap_err();
        assert!(
            err.iter()
                .any(|msg| msg.contains("enables retry") && msg.contains(tag)),
            "expected retry/{tag} conflict, got {err:?}"
        );
    }
}

#[test]
fn backend_tls_sni_with_retry_fails_validate_upstream_references() {
    let mut upstream = make_upstream("sni-upstream");
    upstream.backend_tls_sni = Some("backend.mesh.internal".into());
    let mut proxy = make_proxy("p1", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::HttpsPool;
    proxy.upstream_id = Some("sni-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];
    config.normalize_fields();

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter().any(|msg| {
            msg.contains("enables retry")
                && msg.contains("backend TLS SNI")
                && msg.contains("direct HTTP/2")
        }),
        "expected SNI+retry admission rejection, got {err:?}"
    );
}

#[test]
fn backend_tls_sni_with_grpc_web_buffering_fails_validate() {
    let mut upstream = make_upstream("sni-upstream");
    upstream.backend_tls_sni = Some("backend.mesh.internal".into());
    let mut proxy = make_proxy("p1", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::HttpsPool;
    proxy.upstream_id = Some("sni-upstream".into());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "grpc-web-1".into(),
    }];
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];
    config.plugin_configs = vec![PluginConfig {
        id: "grpc-web-1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "grpc_web".into(),
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".into()),
        enabled: true,
        config: serde_json::json!({}),
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    config.normalize_fields();

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter().any(|msg| {
            msg.contains("request-body-buffering")
                && msg.contains("backend TLS SNI")
                && msg.contains("grpc-web-1")
        }),
        "expected SNI+buffering admission rejection, got {err:?}"
    );
}

#[test]
fn backend_tls_sni_per_port_overlay_with_http2_disabled_fails_validate() {
    let mut upstream = make_upstream("sni-upstream");
    let mut per_port_tls = BackendTlsConfig::default_verify();
    per_port_tls.sni = Some("reviews.mesh.internal".into());
    upstream.port_overrides.insert(
        8443,
        UpstreamPortOverride {
            tls: Some(per_port_tls),
            ..UpstreamPortOverride::default()
        },
    );
    let mut proxy = make_proxy("p1", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::HttpsPool;
    proxy.upstream_id = Some("sni-upstream".into());
    proxy.pool_enable_http2 = Some(false);
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];
    config.normalize_fields();

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter().any(|msg| {
            msg.contains("pool_enable_http2 is false")
                && msg.contains("per-port TLS SNI")
                && msg.contains("reviews.mesh.internal")
        }),
        "expected per-port SNI + http2-disabled rejection, got {err:?}"
    );
}

#[test]
fn backend_tls_sni_without_retry_or_buffering_passes_validate() {
    let mut upstream = make_upstream("sni-upstream");
    upstream.backend_tls_sni = Some("backend.mesh.internal".into());
    let mut proxy = make_proxy("p1", "/api");
    proxy.backend_scheme = Some(BackendScheme::Https);
    proxy.dispatch_kind = DispatchKind::HttpsPool;
    proxy.upstream_id = Some("sni-upstream".into());
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];
    config.normalize_fields();

    assert!(
        config.validate_upstream_references().is_ok(),
        "SNI alone must pass admission under default body limits"
    );
}

#[test]
fn retry_proxy_allows_mesh_transport_target_outside_selected_subset() {
    let mut upstream = make_upstream("mixed-upstream");
    upstream.targets = vec![
        UpstreamTarget {
            host: "plain.local".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: HashMap::from([("version".to_string(), "plain".to_string())]),
            locality: None,
            path: None,
        },
        UpstreamTarget {
            host: "mesh.local".into(),
            port: 8080,
            service_port_policy_key: None,
            weight: 100,
            tags: HashMap::from([
                ("version".to_string(), "mesh".to_string()),
                ("mesh.hbone".to_string(), "true".to_string()),
            ]),
            locality: None,
            path: None,
        },
    ];
    upstream.subsets = Some(vec![ferrum_edge::config::types::SubsetDefinition {
        name: "plain".to_string(),
        labels: HashMap::from([("version".to_string(), "plain".to_string())]),
        traffic_policy: None,
    }]);
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mixed-upstream".into());
    proxy.upstream_subset = Some("plain".into());
    proxy.retry = Some(RetryConfig::default());
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    assert!(config.validate_upstream_references().is_ok());
}

#[test]
fn retry_proxy_rejects_boolish_truthy_mesh_transport_tags() {
    // Runtime treats `1`/`yes`/`on` as truthy for mesh.hbone/mesh.mtls, so the
    // validator must too (otherwise these pass admission then 502 at runtime).
    for value in ["1", "yes", "YES", "on", "True"] {
        let mut upstream = make_upstream("mesh-upstream");
        upstream.targets[0]
            .tags
            .insert("mesh.hbone".to_string(), value.to_string());
        let mut proxy = make_proxy("p1", "/api");
        proxy.upstream_id = Some("mesh-upstream".into());
        proxy.retry = Some(RetryConfig::default());
        let mut config = empty_config();
        config.upstreams = vec![upstream];
        config.proxies = vec![proxy];

        let err = config.validate_upstream_references().unwrap_err();
        assert!(
            err.iter()
                .any(|msg| msg.contains("enables retry") && msg.contains("mesh.hbone")),
            "expected retry/mesh.hbone conflict for tag value {value:?}, got {err:?}"
        );
    }
}

#[test]
fn retry_proxy_rejects_mesh_service_discovery_upstream() {
    // Mesh service-discovery upstreams have empty static targets at admission
    // but later publish HBONE-required targets, so retry conflicts even though
    // no static target carries a mesh tag.
    let mut upstream = make_upstream("mesh-sd-upstream");
    upstream.targets.clear();
    upstream.service_discovery = Some(ferrum_edge::config::types::ServiceDiscoveryConfig {
        provider: ferrum_edge::config::types::SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(ferrum_edge::config::types::MeshSdConfig {
            service_name: "reviews".to_string(),
            namespace: None,
            port: None,
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-sd-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter()
            .any(|msg| msg.contains("enables retry") && msg.contains("mesh.hbone")),
        "expected retry/mesh service-discovery conflict, got {err:?}"
    );
}

#[test]
fn retry_proxy_rejects_sidecar_topology_mesh_service_discovery_upstream() {
    // Sidecar-topology mesh SD publishes `mesh.mtls`-required targets, so the
    // admission conflict must name the mTLS transport, not HBONE.
    let mut upstream = make_upstream("mesh-sd-upstream");
    upstream.targets.clear();
    upstream.service_discovery = Some(ferrum_edge::config::types::ServiceDiscoveryConfig {
        provider: ferrum_edge::config::types::SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(ferrum_edge::config::types::MeshSdConfig {
            service_name: "reviews".to_string(),
            namespace: None,
            port: None,
            poll_interval_seconds: 30,
            topology: ferrum_edge::config::types::MeshSdTopology::Sidecar,
        }),
        default_weight: 1,
    });
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-sd-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter()
            .any(|msg| msg.contains("enables retry") && msg.contains("mesh.mtls")),
        "expected retry/mesh.mtls service-discovery conflict, got {err:?}"
    );
}

#[test]
fn retry_proxy_rejects_mesh_route_dispatch_override_upstream() {
    // A plain default upstream but a mesh_route_dispatch rule that overrides the
    // upstream to a mesh-tagged one must be rejected: matched requests would
    // 502 at runtime.
    let plain = make_upstream("plain-upstream");
    let mut mesh = make_upstream("mesh-upstream");
    mesh.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());

    let dispatch = PluginConfig {
        id: "route-dispatch".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mesh_route_dispatch".into(),
        config: serde_json::json!({
            "rules": [
                { "match": {}, "destination": { "upstream_id": "mesh-upstream" } }
            ]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".into()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("plain-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "route-dispatch".into(),
    }];

    let mut config = empty_config();
    config.upstreams = vec![plain, mesh];
    config.proxies = vec![proxy];
    config.plugin_configs = vec![dispatch];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("enables retry")
            && msg.contains("mesh-upstream")
            && msg.contains("mesh.hbone")),
        "expected retry/route-override conflict, got {err:?}"
    );
}

#[test]
fn retry_proxy_allows_mesh_target_when_status_retries_miss_allowed_methods() {
    // Status-code retries that only apply to methods this proxy cannot serve can
    // never trigger at runtime, so they must not block a mesh-tagged upstream.
    let mut upstream = make_upstream("mesh-upstream");
    upstream.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-upstream".into());
    proxy.allowed_methods = Some(vec!["GET".to_string()]);
    proxy.retry = Some(RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![503],
        retryable_methods: vec!["POST".to_string()],
        retry_on_connect_failure: false,
        ..RetryConfig::default()
    });
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    assert!(
        config.validate_upstream_references().is_ok(),
        "status retries for non-served methods should not block mesh targets"
    );
}

#[test]
fn retry_proxy_rejects_mesh_target_when_status_retries_hit_allowed_methods() {
    // The same config but with an overlapping method (GET) is rejected.
    let mut upstream = make_upstream("mesh-upstream");
    upstream.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-upstream".into());
    proxy.allowed_methods = Some(vec!["GET".to_string()]);
    proxy.retry = Some(RetryConfig {
        max_retries: 3,
        retryable_status_codes: vec![503],
        retryable_methods: vec!["GET".to_string()],
        retry_on_connect_failure: false,
        ..RetryConfig::default()
    });
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter()
            .any(|msg| msg.contains("enables retry") && msg.contains("mesh.hbone")),
        "expected retry/mesh conflict when status retries overlap allowed_methods, got {err:?}"
    );
}

fn mesh_target(host: &str, port: u16) -> UpstreamTarget {
    UpstreamTarget {
        host: host.into(),
        port,
        service_port_policy_key: None,
        weight: 100,
        tags: HashMap::from([("mesh.hbone".to_string(), "true".to_string())]),
        locality: None,
        path: None,
    }
}

#[test]
fn retry_proxy_rejects_when_a_later_mesh_target_port_escapes_the_cap() {
    // The LB can select ANY mesh target. Capping retry to 0 on the FIRST mesh
    // target's port but leaving a second mesh target's port uncapped still 502s
    // when the LB picks the second, so the conflict must be reported.
    use ferrum_edge::config::types::ResolvedPortOverride;
    let mut upstream = make_upstream("mesh-upstream");
    upstream.targets = vec![mesh_target("a.local", 8080), mesh_target("b.local", 9090)];
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    // Cap only the first target's port (8080) to zero.
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        8080_u16,
        ResolvedPortOverride {
            max_retries: Some(0),
            ..ResolvedPortOverride::default()
        },
    )]));
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter()
            .any(|msg| msg.contains("enables retry") && msg.contains("9090")),
        "expected conflict from the uncapped mesh target on port 9090, got {err:?}"
    );
}

#[test]
fn retry_proxy_allows_when_every_mesh_target_port_is_capped_to_zero() {
    // When every selectable mesh target's port zeroes retry, runtime never
    // engages retry on any of them, so HBONE dispatch is preserved end-to-end.
    use ferrum_edge::config::types::ResolvedPortOverride;
    let mut upstream = make_upstream("mesh-upstream");
    upstream.targets = vec![mesh_target("a.local", 8080), mesh_target("b.local", 9090)];
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    let zero = || ResolvedPortOverride {
        max_retries: Some(0),
        ..ResolvedPortOverride::default()
    };
    proxy.dispatch_port_overrides = Some(HashMap::from([(8080_u16, zero()), (9090_u16, zero())]));
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    assert!(
        config.validate_upstream_references().is_ok(),
        "every mesh target's retry is capped to zero; no 502 path remains"
    );
}

#[test]
fn retry_proxy_allows_mesh_target_when_policy_port_cap_zeroes_retry() {
    let mut upstream = make_upstream("mesh-upstream");
    upstream.targets = vec![mesh_target("a.local", 8080)];
    upstream.targets[0].service_port_policy_key = Some(80);
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        80_u16,
        ResolvedPortOverride {
            max_retries: Some(0),
            ..ResolvedPortOverride::default()
        },
    )]));
    let mut config = empty_config();
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    assert!(
        config.validate_upstream_references().is_ok(),
        "the static target dials 8080 but retry is capped by declared Service port 80"
    );
}

#[test]
fn retry_proxy_allows_mesh_service_discovery_when_selected_policy_port_caps_retry() {
    let namespace = ferrum_edge::config::types::default_namespace();
    let mut upstream = make_upstream("mesh-sd-upstream");
    upstream.targets.clear();
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "reviews".into(),
            namespace: None,
            port: None,
            poll_interval_seconds: 30,
            topology: Default::default(),
        }),
        default_weight: 1,
    });
    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-sd-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        80_u16,
        ResolvedPortOverride {
            max_retries: Some(0),
            ..ResolvedPortOverride::default()
        },
    )]));
    let mut config = empty_config();
    config.mesh = Some(Box::new(MeshConfig {
        services: vec![MeshService {
            name: "reviews".into(),
            namespace,
            ports: vec![ServicePort {
                port: 80,
                protocol: AppProtocol::Http,
                name: Some("http".into()),
                target_port: None,
            }],
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
        }],
        ..MeshConfig::default()
    }));
    config.upstreams = vec![upstream];
    config.proxies = vec![proxy];

    assert!(
        config.validate_upstream_references().is_ok(),
        "omitted mesh.port selects Service port 80, whose cap disarms retry before HBONE dispatch"
    );
}

#[test]
fn retry_proxy_rejects_same_upstream_dispatch_rule_that_adds_retry() {
    // Base proxy has NO retry, but a mesh_route_dispatch rule pointing at the
    // SAME (mesh-tagged) default upstream adds its own retry. Runtime applies
    // that rule retry via `route_override_retry` before dispatch, so those
    // matched requests 502 — the same-upstream rule must be evaluated.
    let mut mesh = make_upstream("mesh-upstream");
    mesh.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());

    let dispatch = PluginConfig {
        id: "route-dispatch".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mesh_route_dispatch".into(),
        config: serde_json::json!({
            "rules": [
                {
                    "match": {},
                    "destination": { "upstream_id": "mesh-upstream" },
                    "retry": { "max_retries": 3 }
                }
            ]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".into()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("mesh-upstream".into());
    proxy.retry = None;
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "route-dispatch".into(),
    }];

    let mut config = empty_config();
    config.upstreams = vec![mesh];
    config.proxies = vec![proxy];
    config.plugin_configs = vec![dispatch];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("enables retry")
            && msg.contains("mesh-upstream")
            && msg.contains("mesh.hbone")),
        "expected same-upstream rule-added-retry conflict, got {err:?}"
    );
}

#[test]
fn retry_proxy_allows_when_local_dispatch_shadows_conflicting_global() {
    // A global mesh_route_dispatch routes to a mesh upstream, but the proxy
    // attaches its OWN mesh_route_dispatch (which shadows the global of the same
    // name in PluginCache). The global never runs for this proxy, so its rule
    // must not trigger a spurious rejection.
    let plain = make_upstream("plain-upstream");
    let mut mesh = make_upstream("mesh-upstream");
    mesh.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());

    let global_dispatch = PluginConfig {
        id: "global-dispatch".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mesh_route_dispatch".into(),
        config: serde_json::json!({
            "rules": [
                { "match": {}, "destination": { "upstream_id": "mesh-upstream" } }
            ]
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    // Local instance that shadows the global; routes only to the plain upstream.
    let local_dispatch = PluginConfig {
        id: "local-dispatch".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mesh_route_dispatch".into(),
        config: serde_json::json!({
            "rules": [
                { "match": {}, "destination": { "upstream_id": "plain-upstream" } }
            ]
        }),
        scope: PluginScope::Proxy,
        proxy_id: Some("p1".into()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("plain-upstream".into());
    proxy.retry = Some(RetryConfig::default());
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "local-dispatch".into(),
    }];

    let mut config = empty_config();
    config.upstreams = vec![plain, mesh];
    config.proxies = vec![proxy];
    config.plugin_configs = vec![global_dispatch, local_dispatch];

    assert!(
        config.validate_upstream_references().is_ok(),
        "shadowed global dispatch must not trigger a retry/mesh rejection"
    );
}

#[test]
fn retry_proxy_still_rejects_unshadowed_global_dispatch_to_mesh() {
    // Control for the shadow test: with NO local dispatch, the global rule does
    // apply and the conflict must be reported.
    let plain = make_upstream("plain-upstream");
    let mut mesh = make_upstream("mesh-upstream");
    mesh.targets[0]
        .tags
        .insert("mesh.hbone".to_string(), "true".to_string());

    let global_dispatch = PluginConfig {
        id: "global-dispatch".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mesh_route_dispatch".into(),
        config: serde_json::json!({
            "rules": [
                { "match": {}, "destination": { "upstream_id": "mesh-upstream" } }
            ]
        }),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let mut proxy = make_proxy("p1", "/api");
    proxy.upstream_id = Some("plain-upstream".into());
    proxy.retry = Some(RetryConfig::default());

    let mut config = empty_config();
    config.upstreams = vec![plain, mesh];
    config.proxies = vec![proxy];
    config.plugin_configs = vec![global_dispatch];

    let err = config.validate_upstream_references().unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("enables retry")
            && msg.contains("mesh-upstream")
            && msg.contains("mesh.hbone")),
        "expected unshadowed global dispatch conflict, got {err:?}"
    );
}

// ---- priority_override validation tests ----

#[test]
fn test_plugin_config_priority_override_valid() {
    let pc = PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "rate_limiting".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: Some(5000),
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(pc.validate_fields().is_ok());
}

#[test]
fn test_plugin_config_priority_override_none_valid() {
    let pc = PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "rate_limiting".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(pc.validate_fields().is_ok());
}

#[test]
fn test_plugin_config_priority_override_too_high() {
    let pc = PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "rate_limiting".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: Some(10001),
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let err = pc.validate_fields().unwrap_err();
    assert!(err[0].contains("priority_override must be between 0 and 10000"));
}

#[test]
fn test_plugin_config_priority_override_boundary() {
    let pc = PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "rate_limiting".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: Some(10000),
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(pc.validate_fields().is_ok());
}

#[test]
fn test_plugin_config_priority_override_zero() {
    let pc = PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "rate_limiting".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: Some(0),
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    assert!(pc.validate_fields().is_ok());
}

#[test]
fn test_plugin_config_priority_override_serde_roundtrip() {
    let pc = PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: Some(42),
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let json = serde_json::to_string(&pc).unwrap();
    assert!(json.contains("\"priority_override\":42"));

    let deserialized: PluginConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.priority_override, Some(42));
}

#[test]
fn test_plugin_config_priority_override_absent_in_json() {
    // When priority_override is absent from JSON, it defaults to None
    let json = r#"{
        "id": "pc1",
        "plugin_name": "cors",
        "config": {"allowed_origins": ["*"]},
        "scope": "global",
        "enabled": true
    }"#;
    let pc: PluginConfig = serde_json::from_str(json).unwrap();
    assert_eq!(pc.priority_override, None);
}

#[test]
fn test_plugin_config_priority_override_null_in_json() {
    let json = r#"{
        "id": "pc1",
        "plugin_name": "cors",
        "config": {"allowed_origins": ["*"]},
        "scope": "global",
        "enabled": true,
        "priority_override": null
    }"#;
    let pc: PluginConfig = serde_json::from_str(json).unwrap();
    assert_eq!(pc.priority_override, None);
}

#[test]
fn test_validate_plugin_references_rejects_global_plugin_association() {
    let mut config = empty_config();
    config.plugin_configs = vec![PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    let mut proxy = make_proxy("p1", "/api");
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "pc1".into(),
    }];
    config.proxies = vec![proxy];

    let errs = config.validate_plugin_references().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("proxy-scoped or proxy_group-scoped plugin configs"))
    );
}

#[test]
fn test_validate_plugin_references_rejects_wrong_proxy_target() {
    let mut config = empty_config();
    config.plugin_configs = vec![PluginConfig {
        id: "pc1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "key_auth".into(),
        config: serde_json::json!({}),
        scope: PluginScope::Proxy,
        proxy_id: Some("other-proxy".into()),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    let mut proxy = make_proxy("p1", "/api");
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "pc1".into(),
    }];
    config.proxies = vec![proxy];

    let errs = config.validate_plugin_references().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("targeted to proxy 'other-proxy'"))
    );
}

// ---- ProxyGroup validation tests ----

#[test]
fn test_validate_plugin_references_accepts_proxy_group_association() {
    let mut config = empty_config();
    config.plugin_configs = vec![PluginConfig {
        id: "pg1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    let mut proxy = make_proxy("p1", "/api");
    proxy.plugins = vec![PluginAssociation {
        plugin_config_id: "pg1".into(),
    }];
    config.proxies = vec![proxy];

    // Should pass validation — proxy_group plugins can be referenced by any proxy
    assert!(config.validate_plugin_references().is_ok());
}

#[test]
fn test_validate_plugin_references_proxy_group_shared_across_proxies() {
    let mut config = empty_config();
    config.plugin_configs = vec![PluginConfig {
        id: "pg1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    let mut proxy1 = make_proxy("p1", "/api");
    proxy1.plugins = vec![PluginAssociation {
        plugin_config_id: "pg1".into(),
    }];
    let mut proxy2 = make_proxy("p2", "/web");
    proxy2.plugins = vec![PluginAssociation {
        plugin_config_id: "pg1".into(),
    }];
    config.proxies = vec![proxy1, proxy2];

    // Both proxies can reference the same proxy_group plugin
    assert!(config.validate_plugin_references().is_ok());
}

#[test]
fn test_validate_plugin_references_rejects_proxy_group_with_proxy_id() {
    let mut config = empty_config();
    config.plugin_configs = vec![PluginConfig {
        id: "pg1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::ProxyGroup,
        proxy_id: Some("p1".into()), // Invalid: proxy_group must not have proxy_id
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }];
    config.proxies = vec![make_proxy("p1", "/api")];

    let errs = config.validate_plugin_references().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("proxy_group") && e.contains("must not have proxy_id"))
    );
}

#[test]
fn test_plugin_scope_proxy_group_serde_round_trip() {
    let pc = PluginConfig {
        id: "pg1".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "cors".into(),
        config: serde_json::json!({"allowed_origins": ["*"]}),
        scope: PluginScope::ProxyGroup,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let json = serde_json::to_string(&pc).unwrap();
    assert!(json.contains("\"proxy_group\""));

    let restored: PluginConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.scope, PluginScope::ProxyGroup);
}

// ---- Resource ID validation tests ----

#[test]
fn test_validate_resource_id_valid_uuid() {
    assert!(validate_resource_id("f47ac10b-58cc-4372-a567-0e02b2c3d479").is_ok());
}

#[test]
fn test_validate_resource_id_valid_slug() {
    assert!(validate_resource_id("proxy-httpbin").is_ok());
    assert!(validate_resource_id("consumer.alice").is_ok());
    assert!(validate_resource_id("upstream_backend-v2").is_ok());
    assert!(validate_resource_id("a").is_ok());
    assert!(validate_resource_id("A1").is_ok());
}

#[test]
fn test_validate_resource_id_empty() {
    let err = validate_resource_id("").unwrap_err();
    assert!(err.contains("must not be empty"));
}

#[test]
fn test_validate_resource_id_too_long() {
    let long_id = "a".repeat(255);
    let err = validate_resource_id(&long_id).unwrap_err();
    assert!(err.contains("at most 254"));
}

#[test]
fn test_validate_resource_id_max_length_ok() {
    let id = "a".repeat(254);
    assert!(validate_resource_id(&id).is_ok());
}

#[test]
fn test_validate_resource_id_invalid_start() {
    assert!(validate_resource_id("-proxy").is_err());
    assert!(validate_resource_id(".proxy").is_err());
    assert!(validate_resource_id("_proxy").is_err());
}

#[test]
fn test_validate_resource_id_invalid_chars() {
    assert!(validate_resource_id("proxy httpbin").is_err()); // space
    assert!(validate_resource_id("proxy/httpbin").is_err()); // slash
    assert!(validate_resource_id("proxy@httpbin").is_err()); // at
    assert!(validate_resource_id("proxy!").is_err()); // exclamation
}

// ---- Resource ID format validation on GatewayConfig ----

#[test]
fn test_validate_resource_ids_valid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("proxy-1", "/api")];
    config.consumers = vec![make_consumer("consumer-1", "alice")];
    config.upstreams = vec![make_upstream("upstream-1")];
    assert!(config.validate_resource_ids().is_ok());
}

#[test]
fn test_validate_resource_ids_invalid_proxy_id() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("invalid id!", "/api")];
    let err = config.validate_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Proxy ID"));
}

#[test]
fn test_validate_resource_ids_invalid_consumer_id() {
    let mut config = empty_config();
    config.consumers = vec![make_consumer("bad id", "alice")];
    let err = config.validate_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Consumer ID"));
}

// ---- Resource ID uniqueness tests ----

#[test]
fn test_validate_unique_resource_ids_valid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p2", "/web")];
    config.consumers = vec![make_consumer("c1", "alice"), make_consumer("c2", "bob")];
    assert!(config.validate_unique_resource_ids().is_ok());
}

#[test]
fn test_validate_unique_resource_ids_duplicate_proxy() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p1", "/web")];
    let err = config.validate_unique_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate proxy ID 'p1'"));
}

#[test]
fn test_validate_unique_resource_ids_duplicate_consumer() {
    let mut config = empty_config();
    config.consumers = vec![make_consumer("c1", "alice"), make_consumer("c1", "bob")];
    let err = config.validate_unique_resource_ids().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate consumer ID 'c1'"));
}

#[test]
fn test_validate_unique_resource_ids_allows_consumer_id_in_different_namespaces() {
    let mut config = empty_config();
    let mut prod = make_consumer("c1", "alice");
    prod.namespace = "prod".to_string();
    let mut staging = make_consumer("c1", "bob");
    staging.namespace = "staging".to_string();
    config.consumers = vec![prod, staging];

    assert!(config.validate_unique_resource_ids().is_ok());
}

#[test]
fn test_validate_unique_resource_ids_same_id_different_types_ok() {
    // Same ID across different resource types is fine
    let mut config = empty_config();
    config.proxies = vec![make_proxy("shared-id", "/api")];
    config.consumers = vec![make_consumer("shared-id", "alice")];
    config.upstreams = vec![make_upstream("shared-id")];
    assert!(config.validate_unique_resource_ids().is_ok());
}

// ---- Host validation tests ----

fn make_proxy_with_hosts(id: &str, listen_path: &str, hosts: Vec<&str>) -> Proxy {
    let mut p = make_proxy(id, listen_path);
    p.hosts = hosts.into_iter().map(String::from).collect();
    p
}

#[test]
fn test_validate_host_entry_valid_exact() {
    assert!(validate_host_entry("api.example.com").is_ok());
    assert!(validate_host_entry("example.com").is_ok());
    assert!(validate_host_entry("a.b.c.example.com").is_ok());
    assert!(validate_host_entry("localhost").is_ok());
    assert!(validate_host_entry("my-api.example.com").is_ok());
}

#[test]
fn test_validate_host_entry_valid_wildcard() {
    assert!(validate_host_entry("*.example.com").is_ok());
    assert!(validate_host_entry("*.a.example.com").is_ok());
}

#[test]
fn test_validate_host_entry_rejects_empty_label() {
    let err = validate_host_entry("api..example.com").unwrap_err();
    assert!(err.contains("empty labels"));
}

#[test]
fn test_validate_host_entry_rejects_label_edge_hyphen() {
    let err = validate_host_entry("api.-example.com").unwrap_err();
    assert!(err.contains("start and end"));

    let err = validate_host_entry("api.example-.com").unwrap_err();
    assert!(err.contains("start and end"));
}

#[test]
fn test_validate_host_entry_rejects_oversized_label() {
    let host = format!("{}.example.com", "a".repeat(64));
    let err = validate_host_entry(&host).unwrap_err();
    assert!(err.contains("label longer than 63"));
}

#[test]
fn test_validate_host_entry_rejects_invalid_wildcard_suffix_labels() {
    let err = validate_host_entry("*.api..example.com").unwrap_err();
    assert!(err.contains("empty labels"));

    let err = validate_host_entry("*.api-.example.com").unwrap_err();
    assert!(err.contains("start and end"));
}

#[test]
fn test_validate_host_entry_rejects_scheme() {
    let err = validate_host_entry("http://example.com").unwrap_err();
    assert!(err.contains("scheme"));
}

#[test]
fn test_validate_host_entry_rejects_port() {
    let err = validate_host_entry("example.com:8080").unwrap_err();
    assert!(err.contains("port"));
}

#[test]
fn test_validate_host_entry_rejects_path() {
    let err = validate_host_entry("example.com/path").unwrap_err();
    assert!(err.contains("path"));
}

#[test]
fn test_validate_host_entry_rejects_uppercase() {
    let err = validate_host_entry("API.example.com").unwrap_err();
    assert!(err.contains("lowercase"));
}

#[test]
fn test_validate_host_entry_rejects_invalid_wildcard() {
    // Wildcard not at start
    let err = validate_host_entry("api.*.com").unwrap_err();
    assert!(err.contains("wildcard"));

    // Bare wildcard
    let err = validate_host_entry("*").unwrap_err();
    assert!(err.contains("wildcard"));
}

#[test]
fn test_validate_host_entry_rejects_empty() {
    let err = validate_host_entry("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn test_wildcard_matches_single_level() {
    assert!(wildcard_matches("*.example.com", "api.example.com"));
    assert!(wildcard_matches("*.example.com", "admin.example.com"));
}

#[test]
fn test_wildcard_does_not_match_base_domain() {
    assert!(!wildcard_matches("*.example.com", "example.com"));
}

#[test]
fn test_wildcard_matches_multi_level() {
    assert!(wildcard_matches("*.example.com", "a.b.example.com"));
}

#[test]
fn test_wildcard_matches_exact_pattern() {
    // Non-wildcard pattern should do exact matching
    assert!(wildcard_matches("api.example.com", "api.example.com"));
    assert!(!wildcard_matches("api.example.com", "other.example.com"));
}

#[test]
fn test_hosts_overlap_both_empty_catch_all() {
    // Both catch-all → overlap
    assert!(hosts_overlap(&[], &[]));
}

#[test]
fn test_hosts_overlap_one_empty_catch_all() {
    // Catch-all overlaps with everything
    let hosts = vec!["api.example.com".to_string()];
    assert!(hosts_overlap(&hosts, &[]));
    assert!(hosts_overlap(&[], &hosts));
}

#[test]
fn test_hosts_overlap_disjoint() {
    let a = vec!["api.example.com".to_string()];
    let b = vec!["admin.example.com".to_string()];
    assert!(!hosts_overlap(&a, &b));
}

#[test]
fn test_hosts_overlap_shared_host() {
    let a = vec!["api.example.com".to_string()];
    let b = vec![
        "api.example.com".to_string(),
        "admin.example.com".to_string(),
    ];
    assert!(hosts_overlap(&a, &b));
}

#[test]
fn test_hosts_overlap_wildcard_matches_exact() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["api.example.com".to_string()];
    assert!(hosts_overlap(&a, &b));
}

#[test]
fn test_hosts_overlap_wildcard_no_match() {
    let a = vec!["*.example.com".to_string()];
    let b = vec!["api.other.org".to_string()];
    assert!(!hosts_overlap(&a, &b));
}

// ---- Host+listen_path uniqueness validation tests ----

#[test]
fn test_unique_listen_paths_same_path_disjoint_hosts() {
    // Same listen_path but different hosts → OK
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/api", vec!["admin.example.com"]),
    ];
    assert!(config.validate_unique_listen_paths().is_ok());
}

#[test]
fn test_unique_listen_paths_same_path_overlapping_hosts() {
    // Same listen_path AND overlapping hosts → conflict
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/api", vec!["api.example.com"]),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Overlapping"));
}

#[test]
fn test_unique_listen_paths_allows_same_host_path_in_different_namespaces() {
    let mut tenant_a = make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]);
    tenant_a.namespace = "tenant-a".to_string();
    let mut tenant_b = make_proxy_with_hosts("p2", "/api", vec!["api.example.com"]);
    tenant_b.namespace = "tenant-b".to_string();
    let mut config = empty_config();
    config.proxies = vec![tenant_a, tenant_b];

    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "proxy listen_path uniqueness is namespace-scoped"
    );
}

/// Mesh block for the sibling-exemption tests: one service per entry,
/// `(namespace, name, declared HTTP ports)`. The validator derives sibling
/// identity forward from this, exactly like the router grouping.
fn mesh_block_for_uniqueness(
    services: &[(&str, &str, &[u16])],
) -> Option<Box<ferrum_edge::modes::mesh::config::MeshConfig>> {
    use ferrum_edge::modes::mesh::config::{AppProtocol, MeshConfig, MeshService, ServicePort};
    Some(Box::new(MeshConfig {
        services: services
            .iter()
            .map(|(namespace, name, ports)| MeshService {
                cluster_ips: Vec::new(),
                name: name.to_string(),
                namespace: namespace.to_string(),
                ports: ports
                    .iter()
                    .map(|port| ServicePort {
                        port: *port,
                        protocol: AppProtocol::Http,
                        name: None,
                        target_port: None,
                    })
                    .collect(),
                workloads: Vec::new(),
                protocol_overrides: std::collections::HashMap::new(),
            })
            .collect(),
        ..MeshConfig::default()
    }))
}

#[test]
fn test_unique_listen_paths_exempts_mesh_outbound_per_port_siblings() {
    // Materialized mesh outbound per-port siblings of ONE service share hosts
    // and `/` by design: the route table holds a single lowest-port
    // representative and the request path disambiguates by the captured
    // original-destination port. The uniqueness validator must not reject the
    // slice apply that carries them. Sibling identity is derived from the
    // config's mesh block. (Operator configs can't reach this shape:
    // resource-id validation rejects ids starting with `_`.)
    let mut config = empty_config();
    config.mesh = mesh_block_for_uniqueness(&[("default", "reviews", &[80, 9080])]);
    config.proxies = vec![
        make_proxy_with_hosts(
            "__mesh-outbound-default-reviews-80",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
        make_proxy_with_hosts(
            "__mesh-outbound-default-reviews-9080",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
    ];
    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "same-service per-port outbound siblings must not conflict"
    );
}

#[test]
fn test_unique_listen_paths_exempts_mesh_inbound_per_port_siblings() {
    // Sidecar INBOUND per-port siblings share hosts + `/` exactly like the
    // outbound ones (disambiguated post-match by inbound orig-dst / the
    // request authority port) and get the same same-service exemption.
    let mut config = empty_config();
    config.mesh = mesh_block_for_uniqueness(&[("default", "reviews", &[80, 9080])]);
    config.proxies = vec![
        make_proxy_with_hosts(
            "__mesh-inbound-default-reviews-80",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
        make_proxy_with_hosts(
            "__mesh-inbound-default-reviews-9080",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
    ];
    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "same-service per-port inbound siblings must not conflict"
    );
}

#[test]
fn test_unique_listen_paths_mesh_cross_direction_same_service_still_conflicts() {
    // The owner key is DIRECTION-DISTINCT: an inbound and an outbound route
    // of the SAME service must never legitimately coexist (the outbound
    // materializer yields to existing inbound routes), so their coexistence
    // is a materializer bug that must keep failing validation.
    let mut config = empty_config();
    config.mesh = mesh_block_for_uniqueness(&[("default", "reviews", &[80])]);
    config.proxies = vec![
        make_proxy_with_hosts(
            "__mesh-inbound-default-reviews-80",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
        make_proxy_with_hosts(
            "__mesh-outbound-default-reviews-80",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(
        err.len(),
        1,
        "an inbound/outbound pair of one service must still conflict"
    );
}

#[test]
fn test_unique_listen_paths_mesh_outbound_different_services_still_conflict() {
    // The sibling exemption is keyed on the OWNING SERVICE: two DIFFERENT
    // services' outbound routes overlapping on a host remain a genuine routing
    // ambiguity and must still be rejected — including the lossy `{ns}-{name}`
    // id-join collision (ns `a` / svc `b-c` vs ns `a-b` / svc `c`), which a
    // backwards id parse would have wrongly exempted.
    let mut config = empty_config();
    config.mesh =
        mesh_block_for_uniqueness(&[("default", "reviews", &[80]), ("default", "ratings", &[80])]);
    config.proxies = vec![
        make_proxy_with_hosts(
            "__mesh-outbound-default-reviews-80",
            "/",
            vec!["shared-alias.example.com"],
        ),
        make_proxy_with_hosts(
            "__mesh-outbound-default-ratings-80",
            "/",
            vec!["shared-alias.example.com"],
        ),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1, "cross-service overlap must still conflict");

    // The id-join collision pair: same joined `{ns}-{name}` text, distinct
    // services. Overlapping hosts must still conflict.
    let mut config = empty_config();
    config.mesh = mesh_block_for_uniqueness(&[("a", "b-c", &[80]), ("a-b", "c", &[90])]);
    config.proxies = vec![
        make_proxy_with_hosts("__mesh-outbound-a-b-c-80", "/", vec!["shared.example.com"]),
        make_proxy_with_hosts("__mesh-outbound-a-b-c-90", "/", vec!["shared.example.com"]),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(
        err.len(),
        1,
        "the lossy id-join collision must not be exempted across services"
    );
}

#[test]
fn test_unique_listen_paths_mesh_outbound_without_mesh_block_conflicts() {
    // Without a mesh block claiming the ids (non-mesh modes, hand-crafted
    // configs), reserved-prefix proxies get no exemption.
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts(
            "__mesh-outbound-default-reviews-80",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
        make_proxy_with_hosts(
            "__mesh-outbound-default-reviews-9080",
            "/",
            vec!["reviews.default.svc.cluster.local"],
        ),
    ];
    assert!(
        config.validate_unique_listen_paths().is_err(),
        "unclaimed reserved-prefix proxies must not be exempted"
    );
}

#[test]
fn test_unique_listen_paths_same_path_catchall_conflict() {
    // Two catch-all proxies (no hosts) with same path → conflict
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p2", "/api")];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("Duplicate listen_path"));
}

#[test]
fn test_unique_listen_paths_catchall_vs_specific_host() {
    // Catch-all overlaps with any specific host
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("p1", "/api"),
        make_proxy_with_hosts("p2", "/api", vec!["api.example.com"]),
    ];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
}

#[test]
fn test_unique_listen_paths_allows_exact_host_over_wildcard_same_path() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("exact", "/api", vec!["foo.example.com"]),
        make_proxy_with_hosts("wildcard", "/api", vec!["*.example.com"]),
    ];

    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "router checks exact host routes before wildcard routes, so this overlap is deterministic"
    );
}

#[test]
fn test_unique_listen_paths_different_paths_same_hosts_ok() {
    // Different listen_path → OK even with same hosts
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/web", vec!["api.example.com"]),
    ];
    assert!(config.validate_unique_listen_paths().is_ok());
}

#[test]
fn test_validate_hosts_valid() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy_with_hosts("p1", "/api", vec!["api.example.com"]),
        make_proxy_with_hosts("p2", "/web", vec!["*.example.com"]),
    ];
    assert!(config.validate_hosts().is_ok());
}

#[test]
fn test_validate_hosts_invalid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy_with_hosts("p1", "/api", vec!["INVALID.COM"])];
    let err = config.validate_hosts().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("p1"));
}

#[test]
fn test_normalize_hosts() {
    let mut config = empty_config();
    let mut p = make_proxy("p1", "/api");
    p.hosts = vec!["API.EXAMPLE.COM".to_string()];
    config.proxies = vec![p];
    config.normalize_hosts();
    assert_eq!(config.proxies[0].hosts[0], "api.example.com");
}

#[test]
fn test_hosts_deserialization_default_empty() {
    // When hosts field is missing from JSON, it should default to empty vec
    let json = r#"{
        "id": "p1",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 3000
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert!(proxy.hosts.is_empty());
}

#[test]
fn test_hosts_deserialization_with_values() {
    let json = r#"{
        "id": "p1",
        "hosts": ["api.example.com", "*.example.org"],
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 3000
    }"#;
    let proxy: Proxy = serde_json::from_str(json).unwrap();
    assert_eq!(proxy.hosts, vec!["api.example.com", "*.example.org"]);
}

// ---- Regex listen_path validation tests ----

#[test]
fn test_regex_listen_path_valid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "~/api/v[0-9]+/.*")];
    assert!(config.validate_regex_listen_paths().is_ok());
}

#[test]
fn test_regex_listen_path_valid_literal_trailing_dollar() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", r"~/prices/\$")];
    assert!(config.validate_regex_listen_paths().is_ok());
}

#[test]
fn test_regex_listen_path_invalid_pattern() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "~(invalid[regex")];
    let err = config.validate_regex_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("invalid regex listen_path"));
}

#[test]
fn test_regex_listen_path_empty_pattern() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "~")];
    let err = config.validate_regex_listen_paths().unwrap_err();
    assert_eq!(err.len(), 1);
    assert!(err[0].contains("empty pattern"));
}

#[test]
fn test_regex_listen_path_non_regex_not_checked() {
    // Normal listen_paths should not be validated as regex
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api")];
    assert!(config.validate_regex_listen_paths().is_ok());
}

// ---- Listen path encoded-slash validation tests ----

#[test]
fn test_listen_path_encodings_accepts_clean_paths() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("p1", "/api"),
        make_proxy("p2", "=/exact/path"),
        make_proxy("p3", "~/regex/.*"),
        // A regex listen_path is a pattern, so `\` and `.` are regex syntax
        // there rather than path bytes: `~^/v1\.0/.*` matches the entirely
        // reachable canonical path `/v1.0/x`.
        make_proxy("p4", r"~^/v1\.0/.*"),
        make_proxy("p5", "/v1.0/legacy"),
    ];
    assert!(config.validate_listen_path_encodings().is_ok());
}

#[test]
fn test_listen_path_encodings_rejects_literal_dot_segments_and_backslashes() {
    // No canonical request path can contain a dot segment or a backslash —
    // both are rejected at the frontend boundary — so a literal listen_path
    // carrying one is unreachable config.
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("good", "/api"),
        make_proxy("bad-dotdot", "/api/../legacy"),
        make_proxy("bad-dot", "/api/./legacy"),
        make_proxy("bad-backslash", "/api\\legacy"),
        make_proxy("bad-exact-dotdot", "=/api/../legacy"),
    ];
    let errs = config.validate_listen_path_encodings().unwrap_err();
    assert_eq!(errs.len(), 4);
    assert!(errs.iter().any(|e| e.contains("bad-dotdot")));
    assert!(errs.iter().any(|e| e.contains("bad-dot")));
    assert!(errs.iter().any(|e| e.contains("bad-backslash")));
    assert!(errs.iter().any(|e| e.contains("bad-exact-dotdot")));
    assert!(errs.iter().all(|e| e.contains("canonical policy path")));
}

#[test]
fn test_listen_path_encodings_rejects_escapes_that_cannot_be_forwarded_literally() {
    // An escaped space, brace, or non-ASCII byte is outside the `pchar` decode
    // set, so the runtime refuses any request that spells one — a `listen_path`
    // carrying such an escape can only ever be dead config.
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("good", "/api"),
        make_proxy("bad-space", "/with-space%20here"),
        make_proxy("bad-brace", "/api/%7Bid%7D"),
        make_proxy("bad-utf8", "/caf%C3%A9"),
    ];
    let errs = config.validate_listen_path_encodings().unwrap_err();
    assert_eq!(errs.len(), 3);
    assert!(errs.iter().any(|e| e.contains("bad-space")));
    assert!(errs.iter().any(|e| e.contains("bad-brace")));
    assert!(errs.iter().any(|e| e.contains("bad-utf8")));
    assert!(errs.iter().all(|e| e.contains("canonical policy path")));
}

#[test]
fn test_listen_path_encodings_rejects_single_encoded_slash() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("good", "/api"),
        make_proxy("bad-upper", "/api%2Fadmin"),
        make_proxy("bad-lower", "/foo%2fbar"),
    ];
    let errs = config.validate_listen_path_encodings().unwrap_err();
    assert_eq!(errs.len(), 2);
    assert!(errs.iter().any(|e| e.contains("bad-upper")));
    assert!(errs.iter().any(|e| e.contains("bad-lower")));
    assert!(errs.iter().all(|e| e.contains("canonical policy path")));
}

#[test]
fn test_listen_path_encodings_rejects_ordinary_single_encoding() {
    // The advisory's headline case: `/%61dmin` is not a stricter spelling of
    // `/admin`, it is an unreachable one, because request paths canonicalize
    // before route lookup.
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("good", "/admin"),
        make_proxy("bad", "/%61dmin"),
        make_proxy("bad-dot-segment", "/api/%2e%2e/admin"),
        make_proxy("bad-backslash", "/api%5Cadmin"),
        make_proxy("bad-truncated-escape", "/api%2"),
    ];
    let errs = config.validate_listen_path_encodings().unwrap_err();
    assert_eq!(errs.len(), 4);
    assert!(errs.iter().any(|e| e.contains("bad-dot-segment")));
    assert!(errs.iter().any(|e| e.contains("bad-backslash")));
    assert!(errs.iter().any(|e| e.contains("bad-truncated-escape")));
    assert!(errs.iter().all(|e| e.contains("canonical policy path")));
}

#[test]
fn test_listen_path_encodings_rejects_double_encoded_slash() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("bad-upper", "/api%252Fadmin"),
        make_proxy("bad-lower", "/api%252fadmin"),
    ];
    let errs = config.validate_listen_path_encodings().unwrap_err();
    assert_eq!(errs.len(), 2);
}

#[test]
fn test_listen_path_encodings_rejects_exact_and_regex_forms() {
    let mut config = empty_config();
    config.proxies = vec![
        make_proxy("exact-bad", "=/api%2Fadmin"),
        make_proxy("regex-bad", "~/api%2F.*"),
    ];
    let errs = config.validate_listen_path_encodings().unwrap_err();
    assert_eq!(errs.len(), 2);
}

#[test]
fn test_exact_listen_path_validates() {
    let p = make_proxy("exact-path", "=/api/v1");
    assert!(p.validate_fields().is_ok());
}

#[test]
fn test_exact_listen_path_rejects_missing_slash() {
    let p = make_proxy("bad-exact-path", "=api/v1");
    let errs = p.validate_fields().unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("exact listen_path")),
        "expected exact listen_path error, got {:?}",
        errs
    );
}

#[test]
fn test_exact_listen_path_rejects_empty_path() {
    let p = make_proxy("empty-exact-path", "=");
    let errs = p.validate_fields().unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("exact listen_path")),
        "expected exact listen_path error, got {:?}",
        errs
    );
}

// ---- anchor_regex_pattern tests ----

#[test]
fn test_anchor_regex_pattern_adds_both_anchors() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    assert_eq!(anchor_regex_pattern("/users/[^/]+"), "^(?:/users/[^/]+)$");
}

#[test]
fn test_anchor_regex_pattern_preserves_existing_start() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    assert_eq!(anchor_regex_pattern("^/users/[^/]+"), "^(?:/users/[^/]+)$");
}

#[test]
fn test_anchor_regex_pattern_preserves_existing_end() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    assert_eq!(anchor_regex_pattern("/users/[^/]+$"), "^(?:/users/[^/]+)$");
}

#[test]
fn test_anchor_regex_pattern_preserves_escaped_trailing_dollar() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    assert_eq!(anchor_regex_pattern(r"/prices/\$"), r"^(?:/prices/\$)$");
}

#[test]
fn test_anchor_regex_pattern_preserves_both_existing() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    assert_eq!(anchor_regex_pattern("^/users/[^/]+$"), "^(?:/users/[^/]+)$");
}

#[test]
fn test_anchor_regex_pattern_groups_top_level_alternation() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    assert_eq!(anchor_regex_pattern("/api|/admin"), "^(?:/api|/admin)$");
}

#[test]
fn test_anchor_regex_pattern_wildcard_suffix_preserved() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    // Operators use .* to opt out of strict end-anchoring
    assert_eq!(
        anchor_regex_pattern("/users/[^/]+/orders.*"),
        "^(?:/users/[^/]+/orders.*)$"
    );
}

#[test]
fn test_anchor_regex_pattern_verbose_mode_trailing_comment_stays_valid() {
    use ferrum_edge::config::types::anchor_regex_pattern;

    // Verbose-mode `(?x)` pattern ending in a `#` line comment: the plain
    // `^(?:...)$` wrap would leave the group unclosed (the comment swallows the
    // appended `)$`), so the anchorer terminates the comment with a newline
    // before the close. anchor_regex_pattern only returns this form when it
    // compiles, so this also confirms the result is a valid regex.
    assert_eq!(
        anchor_regex_pattern("(?x)/foo$ # exact route"),
        "^(?:(?x)/foo$ # exact route\n)$"
    );

    // Non-verbose patterns are untouched — no spurious newline (which would be
    // a literal `\n` that breaks matching).
    assert_eq!(anchor_regex_pattern("/users/[^/]+"), "^(?:/users/[^/]+)$");
    assert_eq!(anchor_regex_pattern("/api|/admin"), "^(?:/api|/admin)$");
}

// ---- Stream proxy validation tests ----

#[test]
fn test_stream_proxy_tcp_requires_listen_port() {
    let mut proxy = make_proxy("p1", "/tcp");
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    proxy.listen_port = None;
    let mut config = empty_config();
    config.proxies = vec![proxy];
    let err = config.validate_stream_proxies().unwrap_err();
    assert!(err[0].contains("must have a listen_port"));
}

#[test]
fn test_stream_proxy_tcp_with_listen_port_ok() {
    let mut proxy = make_proxy("p1", "/tcp");
    proxy.backend_scheme = Some(BackendScheme::Tcp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    proxy.listen_port = Some(5432);
    let mut config = empty_config();
    config.proxies = vec![proxy];
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_stream_proxy_duplicate_ports() {
    let mut p1 = make_proxy("p1", "/tcp1");
    p1.backend_scheme = Some(BackendScheme::Tcp);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    p1.listen_port = Some(5432);
    let mut p2 = make_proxy("p2", "/tcp2");
    p2.backend_scheme = Some(BackendScheme::Tcp);
    p2.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    p2.listen_port = Some(5432);
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    let err = config.validate_stream_proxies().unwrap_err();
    assert!(err[0].contains("Duplicate listen_port"));
}

#[test]
fn test_http_proxy_must_not_set_listen_port() {
    let mut proxy = make_proxy("p1", "/api");
    proxy.listen_port = Some(8080);
    let mut config = empty_config();
    config.proxies = vec![proxy];
    let err = config.validate_stream_proxies().unwrap_err();
    assert!(err[0].contains("must not set listen_port"));
}

// ---- Restore pre-deletion validation tests ----
// These test the GatewayConfig validation methods used by handle_restore
// to validate the entire payload before deleting existing data.

#[test]
fn test_restore_payload_valid() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api")];
    config.consumers = vec![make_consumer("c1", "alice")];
    config.upstreams = vec![make_upstream("u1")];
    assert!(config.validate_unique_resource_ids().is_ok());
    assert!(config.validate_unique_consumer_identities().is_ok());
    assert!(config.validate_unique_consumer_credentials().is_ok());
    assert!(config.validate_regex_listen_paths().is_ok());
    assert!(config.validate_unique_listen_paths().is_ok());
    assert!(config.validate_stream_proxies().is_ok());
}

#[test]
fn test_restore_payload_rejects_duplicate_resource_ids() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("same-id", "/a"), make_proxy("same-id", "/b")];
    let err = config.validate_unique_resource_ids().unwrap_err();
    assert!(!err.is_empty());
    assert!(err[0].contains("same-id"));
}

#[test]
fn test_restore_payload_rejects_invalid_regex() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "~(broken[regex")];
    let err = config.validate_regex_listen_paths().unwrap_err();
    assert!(err[0].contains("invalid regex"));
}

#[test]
fn test_restore_payload_rejects_duplicate_listen_paths() {
    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api"), make_proxy("p2", "/api")];
    let err = config.validate_unique_listen_paths().unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn test_restore_payload_ignores_stream_proxy_listen_path_collisions() {
    let mut p1 = make_proxy("p1", "");
    p1.backend_scheme = Some(BackendScheme::Tcp);
    p1.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    p1.listen_port = Some(5432);
    let mut p2 = make_proxy("p2", "");
    p2.backend_scheme = Some(BackendScheme::Udp);
    p2.dispatch_kind = DispatchKind::from(BackendScheme::Udp);
    p2.listen_port = Some(5353);
    let mut config = empty_config();
    config.proxies = vec![p1, p2];
    assert!(config.validate_unique_listen_paths().is_ok());
    assert!(config.validate_regex_listen_paths().is_ok());
}

#[test]
fn test_restore_payload_rejects_missing_upstream_reference() {
    let mut p = make_proxy("p1", "/api");
    p.upstream_id = Some("nonexistent".into());
    let mut config = empty_config();
    config.proxies = vec![p];
    let err = config.validate_upstream_references().unwrap_err();
    assert!(err[0].contains("nonexistent"));
}

#[test]
fn test_restore_payload_accepts_valid_upstream_reference() {
    let mut p = make_proxy("p1", "/api");
    p.upstream_id = Some("u1".into());
    let mut config = empty_config();
    config.proxies = vec![p];
    config.upstreams = vec![make_upstream("u1")];
    assert!(config.validate_upstream_references().is_ok());
}

#[test]
fn test_upstream_target_path_serde_with_path() {
    let target: UpstreamTarget =
        serde_json::from_str(r#"{"host":"a","port":80,"path":"/v2"}"#).unwrap();
    assert_eq!(target.path, Some("/v2".into()));

    let json = serde_json::to_string(&target).unwrap();
    assert!(json.contains(r#""path":"/v2""#));
}

#[test]
fn test_upstream_target_path_serde_without_path() {
    let target: UpstreamTarget = serde_json::from_str(r#"{"host":"a","port":80}"#).unwrap();
    assert_eq!(target.path, None);

    // path should be omitted from serialized output when None
    let json = serde_json::to_string(&target).unwrap();
    assert!(!json.contains("path"));
}

// --- allowed_methods tests ---

#[test]
fn test_proxy_allowed_methods_defaults_to_none() {
    let p = make_proxy("p1", "/api");
    assert!(p.allowed_methods.is_none());
}

#[test]
fn test_proxy_allowed_methods_deserialize_with_methods() {
    let json = serde_json::json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 3000,
        "allowed_methods": ["GET", "POST"]
    });
    let proxy: Proxy = serde_json::from_value(json).unwrap();
    assert_eq!(
        proxy.allowed_methods,
        Some(vec!["GET".to_string(), "POST".to_string()])
    );
}

#[test]
fn test_proxy_allowed_methods_deserialize_null() {
    let json = serde_json::json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 3000,
        "allowed_methods": null
    });
    let proxy: Proxy = serde_json::from_value(json).unwrap();
    assert!(proxy.allowed_methods.is_none());
}

#[test]
fn test_proxy_allowed_methods_deserialize_omitted() {
    let json = serde_json::json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": 3000
    });
    let proxy: Proxy = serde_json::from_value(json).unwrap();
    assert!(proxy.allowed_methods.is_none());
}

#[test]
fn test_proxy_allowed_methods_roundtrip_serialization() {
    let mut p = make_proxy("p1", "/api");
    p.allowed_methods = Some(vec!["GET".into(), "HEAD".into()]);
    let json = serde_json::to_string(&p).unwrap();
    let deserialized: Proxy = serde_json::from_str(&json).unwrap();
    assert_eq!(
        deserialized.allowed_methods,
        Some(vec!["GET".to_string(), "HEAD".to_string()])
    );
}

// ---------------------------------------------------------------------------
// Namespace validation & cross-namespace uniqueness
// ---------------------------------------------------------------------------

#[test]
fn test_validate_namespace_accepts_default() {
    assert!(ferrum_edge::config::types::validate_namespace("ferrum").is_ok());
}

#[test]
fn test_validate_namespace_accepts_alnum_and_separators() {
    for ns in ["prod", "staging-1", "team_alpha", "v0.9", "a1"] {
        assert!(
            ferrum_edge::config::types::validate_namespace(ns).is_ok(),
            "expected {ns} to be valid"
        );
    }
}

#[test]
fn test_validate_namespace_rejects_empty() {
    assert!(ferrum_edge::config::types::validate_namespace("").is_err());
}

#[test]
fn test_validate_namespace_rejects_bad_chars() {
    // Whitespace, slashes, and symbols are rejected by `ID_REGEX`.
    for ns in ["bad ns", "bad/ns", "bad:ns", "bad*ns", "-leadinghyphen"] {
        assert!(
            ferrum_edge::config::types::validate_namespace(ns).is_err(),
            "expected {ns} to be invalid"
        );
    }
}

// The in-memory validators keep proxy uniqueness namespace-scoped. This
// matches the admission-layer and storage invariants, where listen paths and
// ports are unique within a namespace but can be reused by another namespace.
#[test]
fn test_listen_path_validator_is_namespace_scoped() {
    let mut a = make_proxy("p-a", "/shared");
    a.namespace = "prod".to_string();
    let mut b = make_proxy("p-b", "/shared");
    b.namespace = "staging".to_string();

    let config = GatewayConfig {
        proxies: vec![a, b],
        ..Default::default()
    };
    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "duplicate listen_path values in different namespaces should be allowed"
    );
}

// ---- Host-only proxy validation ----

fn make_host_only_proxy(id: &str, hosts: &[&str]) -> Proxy {
    let mut p = make_proxy(id, "/placeholder");
    p.listen_path = None;
    p.hosts = hosts.iter().map(|s| s.to_string()).collect();
    p
}

#[test]
fn test_host_only_proxy_validates() {
    let p = make_host_only_proxy("ho-1", &["api.example.com"]);
    assert!(
        p.validate_fields().is_ok(),
        "host-only proxy with hosts set should validate"
    );
}

#[test]
fn test_http_proxy_rejects_neither_hosts_nor_listen_path() {
    let mut p = make_proxy("catch-all", "/placeholder");
    p.listen_path = None;
    p.hosts = vec![];
    let errs = p.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("hosts") && e.contains("listen_path")),
        "expected error about missing hosts AND listen_path, got {:?}",
        errs
    );
}

#[test]
fn test_http_proxy_rejects_empty_string_listen_path() {
    // `Some("")` is invalid input — must be None or a non-empty string.
    let p = make_proxy("empty-path", "");
    let errs = p.validate_fields().unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("listen_path")),
        "expected rejection of empty-string listen_path, got {:?}",
        errs
    );
}

#[test]
fn test_stream_proxy_with_listen_path_is_rejected() {
    let mut p = make_proxy("stream-with-path", "/nope");
    p.backend_scheme = Some(BackendScheme::Tcp);
    p.dispatch_kind = DispatchKind::from(BackendScheme::Tcp);
    p.listen_port = Some(5432);
    let errs = p.validate_fields().unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("listen_path") && e.contains("stream")),
        "expected stream proxy + listen_path error, got {:?}",
        errs
    );
}

#[test]
fn test_validate_unique_listen_paths_rejects_overlapping_host_only_proxies() {
    let a = make_host_only_proxy("a", &["shared.example.com"]);
    let b = make_host_only_proxy("b", &["shared.example.com"]);
    let config = GatewayConfig {
        proxies: vec![a, b],
        ..Default::default()
    };
    assert!(
        config.validate_unique_listen_paths().is_err(),
        "two host-only proxies on the same host must conflict"
    );
}

#[test]
fn test_validate_unique_listen_paths_allows_disjoint_host_only_proxies() {
    let a = make_host_only_proxy("a", &["a.example.com"]);
    let b = make_host_only_proxy("b", &["b.example.com"]);
    let config = GatewayConfig {
        proxies: vec![a, b],
        ..Default::default()
    };
    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "host-only proxies on disjoint hosts must not conflict"
    );
}

#[test]
fn test_validate_unique_listen_paths_allows_host_only_alongside_path_proxy_same_host() {
    // A host-only proxy and a path-carrying proxy on the same host don't
    // conflict — they occupy different tiers (path first, host-only fallback).
    let mut path_proxy = make_proxy("path", "/api");
    path_proxy.hosts = vec!["shared.example.com".to_string()];
    let host_only = make_host_only_proxy("host-only", &["shared.example.com"]);
    let config = GatewayConfig {
        proxies: vec![path_proxy, host_only],
        ..Default::default()
    };
    assert!(
        config.validate_unique_listen_paths().is_ok(),
        "host-only + path-carrying proxy on same host is allowed (different tiers)"
    );
}

#[test]
fn mesh_tracing_config_deserializes_legacy_singular_provider_alias() {
    let config: MeshTracingConfig = serde_json::from_value(serde_json::json!({
        "provider": {
            "kind": "zipkin",
            "config": {
                "url": "http://zipkin:9411/api/v2/spans"
            }
        }
    }))
    .expect("legacy provider alias deserializes");

    assert_eq!(config.providers.len(), 1);
    match &config.providers[0] {
        TracingProvider::Zipkin { url } => {
            assert_eq!(url, "http://zipkin:9411/api/v2/spans");
        }
        other => panic!("expected Zipkin provider, got {other:?}"),
    }
}

#[test]
fn mesh_tracing_config_deserializes_provider_array() {
    let config: MeshTracingConfig = serde_json::from_value(serde_json::json!({
        "providers": [
            {
                "kind": "zipkin",
                "config": {
                    "url": "http://zipkin:9411/api/v2/spans"
                }
            },
            {
                "kind": "opentelemetry",
                "config": {
                    "endpoint": "http://otel:4318/v1/traces"
                }
            }
        ],
        "disableSpanReporting": true
    }))
    .expect("provider array deserializes");

    assert_eq!(config.disable_span_reporting, Some(true));
    assert_eq!(config.providers.len(), 2);
}

#[test]
fn locality_preference_parse_handles_empty_input() {
    assert_eq!(LocalityPreference::parse(""), None);
    assert_eq!(LocalityPreference::parse("   "), None);
    assert_eq!(LocalityPreference::parse("/zone/sub"), None);
    assert_eq!(LocalityPreference::parse("/"), None);
}

#[test]
fn locality_preference_parse_strips_whitespace() {
    let parsed = LocalityPreference::parse(" us-west / us-west-1 / a ").expect("parses");
    assert_eq!(parsed.region, "us-west");
    assert_eq!(parsed.zone.as_deref(), Some("us-west-1"));
    assert_eq!(parsed.sub_zone.as_deref(), Some("a"));
}

#[test]
fn locality_preference_parse_region_only() {
    let parsed = LocalityPreference::parse("us-west").expect("region-only parses");
    assert_eq!(parsed.region, "us-west");
    assert_eq!(parsed.zone, None);
    assert_eq!(parsed.sub_zone, None);
}

#[test]
fn locality_preference_parse_empty_middle_segment_skips_zone() {
    // `region//sub` — empty zone is dropped (lenient), sub_zone preserved.
    // `same_zone()` against this preference always returns false since
    // `zone` is None — documents and locks the current behavior.
    let parsed = LocalityPreference::parse("region//sub").expect("parses");
    assert_eq!(parsed.region, "region");
    assert_eq!(parsed.zone, None);
    assert_eq!(parsed.sub_zone.as_deref(), Some("sub"));

    let other = LocalityPreference::parse("region/zone/sub").expect("normal triple parses");
    assert!(!parsed.same_zone(&other));
    assert!(parsed.same_region(&other));
}

#[test]
fn locality_preference_parse_glues_extra_slash_into_sub_zone() {
    // splitn(3) glues any trailing slashes into the third segment — locks
    // the current behavior so operators see consistent rank-3 fallback for
    // overlong locality strings rather than silent partial parsing.
    let parsed = LocalityPreference::parse("region/zone/sub/extra").expect("parses");
    assert_eq!(parsed.region, "region");
    assert_eq!(parsed.zone.as_deref(), Some("zone"));
    assert_eq!(parsed.sub_zone.as_deref(), Some("sub/extra"));
}

#[test]
fn locality_preference_tier_helpers_are_consistent() {
    let source = LocalityPreference::parse("us-west/us-west-1/a").expect("source parses");

    let exact = LocalityPreference::parse("us-west/us-west-1/a").expect("exact");
    assert!(source.exact_matches(&exact));
    assert!(source.same_zone(&exact));
    assert!(source.same_region(&exact));

    let same_zone = LocalityPreference::parse("us-west/us-west-1/b").expect("same-zone");
    assert!(!source.exact_matches(&same_zone));
    assert!(source.same_zone(&same_zone));
    assert!(source.same_region(&same_zone));

    let same_region = LocalityPreference::parse("us-west/us-west-2/a").expect("same-region");
    assert!(!source.exact_matches(&same_region));
    assert!(!source.same_zone(&same_region));
    assert!(source.same_region(&same_region));

    let other = LocalityPreference::parse("eu-central/eu-central-1/a").expect("other");
    assert!(!source.exact_matches(&other));
    assert!(!source.same_zone(&other));
    assert!(!source.same_region(&other));
}

#[test]
fn locality_preference_same_zone_requires_zone_present() {
    // Two region-only preferences are in the same region, but neither is in
    // a defined zone — `same_zone` must therefore be false.
    let a = LocalityPreference::parse("us-west").expect("a");
    let b = LocalityPreference::parse("us-west").expect("b");
    assert!(a.same_region(&b));
    assert!(!a.same_zone(&b));
}

// ---- Admin/runtime validation-contract consistency (issue #2158) ----
//
// The admin write path (`PluginConfig::validate_fields`) and the runtime
// rejecting contract shared by database full-loads / CP broadcasts
// (`GatewayConfig::validate_plugin_references`, invoked via
// `collect_rejecting_runtime_config_errors`) MUST agree on which plugin-config
// shapes are admissible. If admin admits a shape the full-load then rejects, the
// database-mode poll loop flips `db_available=false` and wedges the entire admin
// API read-only — the self-DoS in #2158, first surfaced by the
// `test_admin_mongodb_runtime_resource_crud_matrix` functional test which
// created `transaction_log_schema` at proxy_group scope.

fn transaction_log_schema_pc(scope: PluginScope, proxy_id: Option<&str>) -> PluginConfig {
    PluginConfig {
        id: "tls-schema".into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "transaction_log_schema".into(),
        config: serde_json::json!({ "schemas": { "default": { "summary_type": "both" } } }),
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn prometheus_metrics_pc(id: &str, scope: PluginScope, proxy_id: Option<&str>) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "prometheus_metrics".into(),
        config: serde_json::json!({}),
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn transaction_log_schema_global_scope_admitted_by_both_surfaces() {
    let pc = transaction_log_schema_pc(PluginScope::Global, None);
    assert!(
        pc.validate_fields().is_ok(),
        "admin write path should admit transaction_log_schema at global scope"
    );

    let mut config = empty_config();
    config.plugin_configs = vec![pc];
    assert!(
        config.validate_plugin_references().is_ok(),
        "runtime rejecting contract should admit transaction_log_schema at global scope"
    );
}

#[test]
fn transaction_log_schema_proxy_group_scope_rejected_by_both_surfaces() {
    let pc = transaction_log_schema_pc(PluginScope::ProxyGroup, None);

    // Admin write path must fail closed at write time (4xx), mirroring the
    // runtime rejecting contract — this is the fix for #2158. Before the fix
    // `validate_fields` admitted this shape and only the full-load rejected it,
    // wedging the DB poll loop.
    let field_errors = pc
        .validate_fields()
        .expect_err("admin write path must reject transaction_log_schema at proxy_group scope");
    assert!(
        field_errors
            .iter()
            .any(|m| m.contains("transaction_log_schema") && m.contains("scope 'global'")),
        "unexpected validate_fields errors: {field_errors:?}"
    );

    let mut config = empty_config();
    config.plugin_configs = vec![pc];
    let ref_errors = config.validate_plugin_references().expect_err(
        "runtime rejecting contract must reject transaction_log_schema at proxy_group scope",
    );
    assert!(
        ref_errors
            .iter()
            .any(|m| m.contains("transaction_log_schema") && m.contains("scope 'global'")),
        "unexpected validate_plugin_references errors: {ref_errors:?}"
    );
}

#[test]
fn transaction_log_schema_proxy_scope_rejected_by_both_surfaces() {
    // proxy_id points at an existing proxy so the ONLY disagreement under test
    // is the transaction_log_schema global-scope invariant, not a dangling ref.
    let pc = transaction_log_schema_pc(PluginScope::Proxy, Some("p1"));

    let field_errors = pc
        .validate_fields()
        .expect_err("admin write path must reject transaction_log_schema at proxy scope");
    assert!(
        field_errors
            .iter()
            .any(|m| m.contains("transaction_log_schema") && m.contains("scope 'global'")),
        "unexpected validate_fields errors: {field_errors:?}"
    );

    let mut config = empty_config();
    config.proxies = vec![make_proxy("p1", "/api")];
    config.plugin_configs = vec![pc];
    let ref_errors = config
        .validate_plugin_references()
        .expect_err("runtime rejecting contract must reject transaction_log_schema at proxy scope");
    assert!(
        ref_errors
            .iter()
            .any(|m| m.contains("transaction_log_schema") && m.contains("scope 'global'")),
        "unexpected validate_plugin_references errors: {ref_errors:?}"
    );
}

#[test]
fn prometheus_metrics_requires_global_scope_on_both_validation_surfaces() {
    for (scope, proxy_id) in [
        (PluginScope::ProxyGroup, None),
        (PluginScope::Proxy, Some("p1")),
    ] {
        let pc = prometheus_metrics_pc("prometheus", scope, proxy_id);
        let field_errors = pc
            .validate_fields()
            .expect_err("admin validation must reject scoped prometheus_metrics");
        assert!(field_errors.iter().any(|error| {
            error.contains("prometheus_metrics") && error.contains("scope 'global'")
        }));

        let mut config = empty_config();
        config.proxies = vec![make_proxy("p1", "/api")];
        config.plugin_configs = vec![pc];
        let reference_errors = config
            .validate_plugin_references()
            .expect_err("runtime validation must reject scoped prometheus_metrics");
        assert!(reference_errors.iter().any(|error| {
            error.contains("prometheus_metrics") && error.contains("scope 'global'")
        }));
    }
}

#[test]
fn prometheus_metrics_rejects_duplicate_enabled_global_instances() {
    let mut config = empty_config();
    config.plugin_configs = vec![
        prometheus_metrics_pc("prometheus-a", PluginScope::Global, None),
        prometheus_metrics_pc("prometheus-b", PluginScope::Global, None),
    ];

    let errors = config
        .validate_plugin_references()
        .expect_err("one process may have only one enabled Prometheus registry owner");
    assert!(errors.iter().any(|error| {
        error.contains("at most one enabled global instance")
            && error.contains("prometheus-a")
            && error.contains("prometheus-b")
    }));

    config.plugin_configs[1].enabled = false;
    assert!(config.validate_plugin_references().is_ok());
}

#[test]
fn api_chargeback_rejects_duplicate_effective_instances_on_one_proxy() {
    let mut config = empty_config();
    let mut proxy = make_proxy("p1", "/api");
    proxy.plugins = vec![
        PluginAssociation {
            plugin_config_id: "charge-a".into(),
        },
        PluginAssociation {
            plugin_config_id: "charge-b".into(),
        },
    ];
    config.proxies = vec![proxy];
    config.plugin_configs = vec![
        PluginConfig {
            id: "charge-a".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "api_chargeback".into(),
            config: serde_json::json!({
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
                "cleanup_interval_seconds": 0
            }),
            scope: PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        PluginConfig {
            id: "charge-b".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "api_chargeback".into(),
            config: serde_json::json!({
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.02}],
                "cleanup_interval_seconds": 0
            }),
            scope: PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    let errors = config
        .validate_plugin_references()
        .expect_err("duplicate effective api_chargeback must be rejected");
    assert!(errors.iter().any(|error| {
        error.contains("at most one effective instance per proxy")
            && error.contains("charge-a")
            && error.contains("charge-b")
    }));
}

#[test]
fn api_chargeback_rejects_conflicting_shared_tunables_in_plugin_references() {
    let mut config = empty_config();
    let mut p1 = make_proxy("p1", "/api");
    p1.plugins = vec![PluginAssociation {
        plugin_config_id: "charge-a".into(),
    }];
    let mut p2 = make_proxy("p2", "/web");
    p2.plugins = vec![PluginAssociation {
        plugin_config_id: "charge-b".into(),
    }];
    config.proxies = vec![p1, p2];
    config.plugin_configs = vec![
        PluginConfig {
            id: "charge-a".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "api_chargeback".into(),
            config: serde_json::json!({
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
                "render_cache_ttl_seconds": 5,
                "cleanup_interval_seconds": 0
            }),
            scope: PluginScope::Proxy,
            proxy_id: Some("p1".into()),
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        PluginConfig {
            id: "charge-b".into(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "api_chargeback".into(),
            config: serde_json::json!({
                "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
                "render_cache_ttl_seconds": 60,
                "cleanup_interval_seconds": 0
            }),
            scope: PluginScope::Proxy,
            proxy_id: Some("p2".into()),
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    let errors = config
        .validate_plugin_references()
        .expect_err("disagreeing shared tunables must be rejected");
    assert!(errors.iter().any(|error| {
        error.contains("shared render/cleanup tunables must match")
            && error.contains("charge-a")
            && error.contains("charge-b")
    }));
}

#[test]
fn admin_admitted_plugin_scope_implies_runtime_reference_admit() {
    // Invariant guarding the whole functional CRUD matrix: for the proxy_group
    // scope the matrix assigns to every plugin, if the admin write path admits a
    // plugin config, the runtime rejecting contract must admit it too. This is
    // the per-plugin form of "admin-accept implies fullload-accept" and would
    // catch any future single-resource plugin-scope rule that lands in
    // `validate_plugin_references` but not in `validate_fields`.
    for plugin_name in ferrum_edge::plugins::available_plugins() {
        let pc = PluginConfig {
            id: format!("pc-{plugin_name}"),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: plugin_name.to_string(),
            // Field/reference validation does not schema-check `config`; an empty
            // object exercises the scope/reference contract without per-plugin
            // fixtures.
            config: serde_json::json!({}),
            scope: PluginScope::ProxyGroup,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        if pc.validate_fields().is_err() {
            // Admin rejects this shape (e.g. transaction_log_schema at
            // proxy_group scope after the #2158 fix); the implication holds
            // vacuously, and the runtime is free to reject it too.
            continue;
        }

        let mut config = empty_config();
        config.plugin_configs = vec![pc];
        assert!(
            config.validate_plugin_references().is_ok(),
            "plugin '{plugin_name}' is admitted by the admin write path at proxy_group scope but \
             rejected by the runtime rejecting contract — this admit/reject skew wedges the DB \
             poll loop (issue #2158)"
        );
    }
}

// ── request_deduplication / mcp_gateway replay-provenance composition ────────
//
// A `request_deduplication` hit short-circuits `before_proxy` at priority 2750,
// ahead of `mcp_gateway` at 2992, and serves a *finalized* representation whose
// presentation transforms are deliberately skipped. `mcp_gateway`'s public
// URI/name rewrite is resolved against a per-session catalog re-listed from
// upstream on a discovery TTL, so nothing computed from configuration can prove
// a stored replay still matches the live mapping. Admission refuses the pair
// rather than replaying under an unprovable policy.

fn dedup_plugin_config(id: &str, scope: PluginScope, proxy_id: Option<&str>) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "request_deduplication".into(),
        config: serde_json::json!({}),
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn mcp_gateway_plugin_config(id: &str, scope: PluginScope, proxy_id: Option<&str>) -> PluginConfig {
    PluginConfig {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "mcp_gateway".into(),
        config: serde_json::json!({
            "enabled": true,
            "mode": "aggregate_router",
            "endpoint": {"path": "/mcp", "protocol_versions": ["2025-11-25"]},
            "servers": {
                "github": {
                    "upstream_url": "http://mcp-alpha:8080",
                    "namespace": "github",
                    "enabled": true,
                }
            },
        }),
        scope,
        proxy_id: proxy_id.map(str::to_string),
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn associate(proxy: &mut Proxy, plugin_config_ids: &[&str]) {
    proxy.plugins = plugin_config_ids
        .iter()
        .map(|id| PluginAssociation {
            plugin_config_id: (*id).to_string(),
        })
        .collect();
}

#[test]
fn dedup_and_mcp_gateway_on_one_proxy_are_rejected() {
    let mut config = empty_config();
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp_gateway_plugin_config("mcp1", PluginScope::Proxy, Some("p1")),
    ];
    let mut proxy = make_proxy("p1", "/api");
    associate(&mut proxy, &["dedup1", "mcp1"]);
    config.proxies = vec![proxy];

    let errs = config
        .validate_plugin_references()
        .expect_err("dedup + mcp_gateway on one proxy must be refused");
    let joined = errs.join("; ");
    assert!(
        joined.contains("request_deduplication cannot be composed with mcp_gateway"),
        "unexpected errors: {joined}"
    );
    // Operators need both offending ids to act on the error.
    assert!(
        joined.contains("dedup1") && joined.contains("mcp1"),
        "{joined}"
    );
    assert!(joined.contains("p1"), "{joined}");
}

#[test]
fn dedup_and_a_global_mcp_gateway_are_rejected() {
    // The global instance is effective on every proxy that has no local
    // `mcp_gateway`, so it composes with a proxy-scoped dedup just the same.
    let mut config = empty_config();
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp_gateway_plugin_config("mcp-global", PluginScope::Global, None),
    ];
    let mut proxy = make_proxy("p1", "/api");
    associate(&mut proxy, &["dedup1"]);
    config.proxies = vec![proxy];

    let errs = config
        .validate_plugin_references()
        .expect_err("a global mcp_gateway still composes with a proxy-scoped dedup");
    assert!(
        errs.iter()
            .any(|e| e.contains("request_deduplication cannot be composed with mcp_gateway")),
        "unexpected errors: {errs:?}"
    );
}

#[test]
fn a_disabled_mcp_gateway_does_not_block_dedup() {
    let mut config = empty_config();
    let mut mcp = mcp_gateway_plugin_config("mcp1", PluginScope::Proxy, Some("p1"));
    mcp.enabled = false;
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp,
    ];
    let mut proxy = make_proxy("p1", "/api");
    associate(&mut proxy, &["dedup1", "mcp1"]);
    config.proxies = vec![proxy];

    assert!(
        config.validate_plugin_references().is_ok(),
        "a disabled mcp_gateway applies no rewrite and must not block deduplication"
    );
}

#[test]
fn an_internally_disabled_mcp_gateway_does_not_block_dedup() {
    let mut config = empty_config();
    let mut mcp = mcp_gateway_plugin_config("mcp1", PluginScope::Proxy, Some("p1"));
    mcp.config["enabled"] = serde_json::Value::Bool(false);
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp,
    ];
    let mut proxy = make_proxy("p1", "/api");
    associate(&mut proxy, &["dedup1", "mcp1"]);
    config.proxies = vec![proxy];

    assert!(
        config.validate_plugin_references().is_ok(),
        "an internally disabled mcp_gateway applies no rewrite and must not block deduplication"
    );
}

#[test]
fn dedup_and_mcp_gateway_on_separate_proxies_are_admitted() {
    // The documented remedy: keep both behaviors by splitting them across
    // proxies, where no replay is ever served under the MCP mapping.
    let mut config = empty_config();
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp_gateway_plugin_config("mcp1", PluginScope::Proxy, Some("p2")),
    ];
    let mut dedup_proxy = make_proxy("p1", "/api");
    associate(&mut dedup_proxy, &["dedup1"]);
    let mut mcp_proxy = make_proxy("p2", "/mcp");
    associate(&mut mcp_proxy, &["mcp1"]);
    config.proxies = vec![dedup_proxy, mcp_proxy];

    assert!(
        config.validate_plugin_references().is_ok(),
        "the two plugins on separate proxies never compose and must be admitted"
    );
}

#[test]
fn a_proxy_local_mcp_gateway_shadowing_a_global_one_is_still_rejected() {
    // Scope resolution must mirror the runtime merge: the local instance
    // replaces the global for this proxy, and it is still effective.
    let mut config = empty_config();
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp_gateway_plugin_config("mcp-global", PluginScope::Global, None),
        mcp_gateway_plugin_config("mcp-local", PluginScope::Proxy, Some("p1")),
    ];
    let mut proxy = make_proxy("p1", "/api");
    associate(&mut proxy, &["dedup1", "mcp-local"]);
    config.proxies = vec![proxy];

    let errs = config
        .validate_plugin_references()
        .expect_err("a proxy-local mcp_gateway is effective and must be refused");
    let joined = errs.join("; ");
    assert!(
        joined.contains("mcp-local"),
        "the effective local instance must be named: {joined}"
    );
    assert!(
        !joined.contains("mcp-global"),
        "the shadowed global instance is not effective on this proxy: {joined}"
    );
}

#[test]
fn a_global_mcp_gateway_in_another_namespace_does_not_block_dedup() {
    // Globals are namespace-partitioned by the runtime merge (each proxy takes
    // only the globals of its own namespace), so a global `mcp_gateway` in one
    // tenant must not refuse deduplication in another.
    let mut config = empty_config();
    let mut dedup = dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1"));
    dedup.namespace = "tenant-a".to_string();
    let mut mcp = mcp_gateway_plugin_config("mcp-global", PluginScope::Global, None);
    mcp.namespace = "tenant-b".to_string();
    config.plugin_configs = vec![dedup, mcp];
    let mut proxy = make_proxy("p1", "/api");
    proxy.namespace = "tenant-a".to_string();
    associate(&mut proxy, &["dedup1"]);
    config.proxies = vec![proxy];

    assert!(
        config.validate_plugin_references().is_ok(),
        "a global mcp_gateway is never merged into a proxy in a different namespace"
    );
}

#[test]
fn an_internally_disabled_local_mcp_gateway_shadows_an_enabled_global_one() {
    // The runtime decides shadowing on the outer `enabled` flag alone: the
    // local instance is constructed and replaces the global for this proxy even
    // though its inner switch is off. Resolving the effective set before asking
    // which members are active is what keeps this composition admitted.
    let mut config = empty_config();
    let mut local = mcp_gateway_plugin_config("mcp-local", PluginScope::Proxy, Some("p1"));
    local.config["enabled"] = serde_json::Value::Bool(false);
    config.plugin_configs = vec![
        dedup_plugin_config("dedup1", PluginScope::Proxy, Some("p1")),
        mcp_gateway_plugin_config("mcp-global", PluginScope::Global, None),
        local,
    ];
    let mut proxy = make_proxy("p1", "/api");
    associate(&mut proxy, &["dedup1", "mcp-local"]);
    config.proxies = vec![proxy];

    assert!(
        config.validate_plugin_references().is_ok(),
        "the effective mcp_gateway on this proxy is the internally disabled local instance, \
         which applies no rewrite"
    );
}
