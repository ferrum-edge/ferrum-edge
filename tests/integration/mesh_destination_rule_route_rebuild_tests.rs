//! #3243: DestinationRule-only edits must atomically republish route-held
//! `Arc<Proxy>` projections before any programmed-status / revision ACK.
//!
//! `ConfigDelta` keys on resource `updated_at`, but DR-derived proxy fields
//! (`dispatch_port_overrides`, `dispatch_port_override_fallback`,
//! `resolved_tls`) are `#[serde(skip)]`. These tests drive the live
//! `ProxyState::update_config` path — including the empty-delta publish
//! branch — so a DR-only create/update/removal cannot leave stale route
//! snapshots until an unrelated proxy edit.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use ferrum_edge::config::types::{
    Consumer, DnsSdConfig, GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, MeshSdConfig,
    Proxy, SdProvider, ServiceDiscoveryConfig, Upstream, UpstreamLocalityLbSetting,
    UpstreamPortOverride, UpstreamTarget,
};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::load_balancer::{HashOnStrategy, LoadBalancerCache};
use ferrum_edge::modes::mesh::config::{
    MeshConfig, MeshConnectionPoolHttp, MeshDestinationRule, MeshTrafficPolicy,
    MeshTrafficPolicyTls, MtlsMode,
};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};

use super::mesh_test_support::{service_for, workload_for};

fn runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        stock_xds_urls: Vec::new(),
        stock_xds_node_id: None,
        stock_xds_node_metadata: Default::default(),
        stock_xds_token_file: None,
        stock_xds_limits: Default::default(),
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        egress_gateway: None,
        workload_spiffe_id: None,
        waypoint_name: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        unix_socket_allowed_roots: Vec::new(),
        unix_socket_allowed_uids: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: "cluster.local".to_string(),
        capture_mode: ferrum_edge::capture::CaptureMode::Explicit,
        outbound_traffic_policy: ferrum_edge::modes::mesh::config::OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

fn mesh_env() -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::Mesh,
        ..EnvConfig::default()
    }
}

fn http_proxy() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "reviews-p",
        "namespace": "default",
        "hosts": ["reviews.example.com"],
        "listen_path": "/http",
        "backend_host": "reviews.default.svc.cluster.local",
        "backend_port": 0,
        "backend_scheme": "http",
        "upstream_id": "reviews-u"
    }))
    .expect("proxy fixture")
}

fn unrelated_http_proxy() -> Proxy {
    serde_json::from_value(serde_json::json!({
        "id": "ratings-p",
        "namespace": "default",
        "hosts": ["ratings.example.com"],
        "listen_path": "/ratings",
        "backend_host": "ratings.default.svc.cluster.local",
        "backend_port": 8080,
        "backend_scheme": "http"
    }))
    .expect("unrelated proxy fixture")
}

fn unrelated_consumer(id: &str, username: &str) -> Consumer {
    let now = Utc::now();
    Consumer {
        id: id.to_string(),
        username: username.to_string(),
        namespace: "default".to_string(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: now,
        updated_at: now,
    }
}

fn lb_effective_algorithm(state: &ProxyState, port: Option<u16>) -> LoadBalancerAlgorithm {
    let snapshot = state.load_balancer_cache.load();
    LoadBalancerCache::effective_algorithm_from(&snapshot, "default", "reviews-u", port, None)
        .expect("reviews upstream balancer")
}

fn lb_hash_on_for_port(state: &ProxyState, port: u16) -> HashOnStrategy {
    let snapshot = state.load_balancer_cache.load();
    LoadBalancerCache::get_hash_on_strategy_for_port_from(&snapshot, "default", "reviews-u", port)
}

fn sd_upstream() -> Upstream {
    let now = Utc::now();
    Upstream {
        id: "reviews-u".to_string(),
        namespace: "default".to_string(),
        name: Some("reviews.default.svc.cluster.local".to_string()),
        targets: vec![UpstreamTarget {
            host: "reviews.default.svc.cluster.local".to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: Some(ServiceDiscoveryConfig {
            provider: SdProvider::DnsSd,
            dns_sd: Some(DnsSdConfig {
                service_name: "_http._tcp.reviews.default.svc.cluster.local".to_string(),
                poll_interval_seconds: 30,
            }),
            kubernetes: None,
            consul: None,
            mesh: None,
            default_weight: 1,
            max_stale_seconds: None,
            stale_policy: None,
        }),
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
        source_labels: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn unrelated_upstream() -> Upstream {
    let mut upstream = sd_upstream();
    upstream.id = "ratings-u".to_string();
    upstream.name = Some("ratings.default.svc.cluster.local".to_string());
    upstream.targets[0].host = "ratings.default.svc.cluster.local".to_string();
    upstream
}

fn destination_rule(idle_ms: Option<u64>, tls_sni: Option<&str>) -> MeshDestinationRule {
    MeshDestinationRule {
        name: "reviews-dr".to_string(),
        namespace: "default".to_string(),
        host: "reviews.default.svc.cluster.local".to_string(),
        traffic_policy: Some(MeshTrafficPolicy {
            connection_pool_http: idle_ms.map(|ms| MeshConnectionPoolHttp {
                idle_timeout_ms: Some(ms),
                ..MeshConnectionPoolHttp::default()
            }),
            tls: tls_sni.map(|sni| MeshTrafficPolicyTls {
                mode: MtlsMode::Simple,
                sni: Some(sni.to_string()),
                ..MeshTrafficPolicyTls::default()
            }),
            ..MeshTrafficPolicy::default()
        }),
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
        // Mesh-wide, matching the Kubernetes translator's default for an
        // omitted `spec.exportTo`. This fixture pre-dates export visibility, so
        // an empty list here would make the rule namespace-local on the native
        // carrier and silently change what this route-rebuild test exercises.
        export_to: vec!["*".to_string()],
    }
}

/// Production mesh applies these reserved resources through
/// `ProxyState::update_mesh_config` with trusted materialization IDs. That
/// entrypoint is intentionally crate-private, so external tests using the
/// public update path remove the unrelated generated plugins and exercise the
/// same request-epoch publication with ordinary resources.
fn remove_trusted_mesh_plugins_for_public_update_fixture(config: &mut GatewayConfig) {
    config
        .plugin_configs
        .retain(|plugin| !plugin.id.starts_with("__mesh_"));
    for proxy in &mut config.proxies {
        proxy
            .plugins
            .retain(|association| !association.plugin_config_id.starts_with("__mesh_"));
    }
}

fn prepared_with_dr_at(
    dr: Option<MeshDestinationRule>,
    stamp: chrono::DateTime<Utc>,
) -> GatewayConfig {
    let mut proxy = http_proxy();
    proxy.created_at = stamp;
    proxy.updated_at = stamp;
    let mut upstream = sd_upstream();
    upstream.created_at = stamp;
    upstream.updated_at = stamp;
    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(MeshConfig {
            destination_rules: dr.into_iter().collect(),
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    let mut prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh prepare");
    // Stabilize operator-authored proxy timestamps so DR-only prepares do not
    // accidentally look like Proxy resource edits.
    for proxy in &mut prepared.proxies {
        if proxy.id == "reviews-p" {
            proxy.created_at = stamp;
            proxy.updated_at = stamp;
        }
    }
    remove_trusted_mesh_plugins_for_public_update_fixture(&mut prepared);
    prepared
}

fn prepared_with_dr(dr: Option<MeshDestinationRule>) -> GatewayConfig {
    prepared_with_dr_at(dr, Utc::now() - Duration::seconds(30))
}

fn prepared_mesh_sd_with_dr(stamp: chrono::DateTime<Utc>, idle_ms: u64) -> GatewayConfig {
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.9"]);
    let service = service_for("reviews", "default", &[&workload]);
    let mut proxy = http_proxy();
    proxy.created_at = stamp;
    proxy.updated_at = stamp;
    let mut upstream = sd_upstream();
    upstream.targets.clear();
    upstream.service_discovery = Some(ServiceDiscoveryConfig {
        provider: SdProvider::Mesh,
        dns_sd: None,
        kubernetes: None,
        consul: None,
        mesh: Some(MeshSdConfig {
            service_name: "reviews".to_string(),
            namespace: Some("default".to_string()),
            port: Some(8080),
            poll_interval_seconds: 300,
            topology: Default::default(),
        }),
        default_weight: 1,
        max_stale_seconds: None,
        stale_policy: None,
    });
    upstream.created_at = stamp;
    upstream.updated_at = stamp;
    let mut config = GatewayConfig {
        proxies: vec![proxy],
        upstreams: vec![upstream],
        mesh: Some(Box::new(MeshConfig {
            services: vec![service],
            workloads: vec![workload],
            destination_rules: vec![destination_rule(Some(idle_ms), None)],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    let mut prepared = prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh prepare");
    for proxy in &mut prepared.proxies {
        proxy.created_at = stamp;
        proxy.updated_at = stamp;
    }
    for upstream in &mut prepared.upstreams {
        upstream.created_at = stamp;
        upstream.updated_at = stamp;
    }
    // `prepare_gateway_config_for_mesh` also materializes reserved
    // `__mesh-*` routes/upstreams. Production publishes those through the
    // crate-private trusted mesh entrypoint, while this integration test must
    // use the public validation path. Keep only the operator-authored SD pair
    // under test so public validation does not reject unrelated reserved IDs.
    prepared.proxies.retain(|proxy| proxy.id == "reviews-p");
    prepared
        .upstreams
        .retain(|upstream| upstream.id == "reviews-u");
    remove_trusted_mesh_plugins_for_public_update_fixture(&mut prepared);
    prepared
}

fn route_fallback_idle_ms(state: &ProxyState) -> Option<u64> {
    state
        .router_cache
        .find_proxy(Some("reviews.example.com"), "/http")
        .expect("route present")
        .proxy
        .dispatch_port_override_fallback
        .as_ref()
        .and_then(|override_config| override_config.http_idle_timeout_ms)
}

fn route_tls_sni(state: &ProxyState) -> Option<String> {
    state
        .router_cache
        .find_proxy(Some("reviews.example.com"), "/http")
        .expect("route present")
        .proxy
        .resolved_tls
        .sni
        .clone()
}

fn route_port_override(
    state: &ProxyState,
    port: u16,
) -> Option<ferrum_edge::config::types::ResolvedPortOverride> {
    state
        .router_cache
        .find_proxy(Some("reviews.example.com"), "/http")
        .expect("route present")
        .proxy
        .dispatch_port_overrides
        .as_ref()
        .and_then(|overrides| overrides.get(&port))
        .cloned()
}

fn route_fallback_max_retries(state: &ProxyState) -> Option<u32> {
    state
        .router_cache
        .find_proxy(Some("reviews.example.com"), "/http")
        .expect("route present")
        .proxy
        .dispatch_port_override_fallback
        .as_ref()
        .and_then(|override_config| override_config.max_retries)
}

fn new_proxy_state(config: GatewayConfig) -> (ProxyState, Vec<tokio::task::JoinHandle<()>>) {
    let dns_cache = DnsCache::new(DnsConfig::default());
    ProxyState::new(config, dns_cache, mesh_env(), None, None).expect("ProxyState")
}

/// Same serialized proxy/upstream timestamps, different `#[serde(skip)]`
/// projections — the empty-ConfigDelta DR-only shape that previously reused a
/// stale route table until an unrelated event.
fn projected_only_configs(
    mutate_old: impl FnOnce(&mut Upstream),
    mutate_new: impl FnOnce(&mut Upstream),
) -> (GatewayConfig, GatewayConfig) {
    projected_only_configs_with_extra_proxies(mutate_old, mutate_new, Vec::new())
}

fn projected_only_configs_with_extra_proxies(
    mutate_old: impl FnOnce(&mut Upstream),
    mutate_new: impl FnOnce(&mut Upstream),
    extra_proxies: Vec<Proxy>,
) -> (GatewayConfig, GatewayConfig) {
    let stamp = Utc::now();
    let mut old_upstream = sd_upstream();
    old_upstream.created_at = stamp;
    old_upstream.updated_at = stamp;
    mutate_old(&mut old_upstream);

    let mut new_upstream = sd_upstream();
    new_upstream.created_at = stamp;
    new_upstream.updated_at = stamp;
    mutate_new(&mut new_upstream);

    let mut proxy = http_proxy();
    proxy.created_at = stamp;
    proxy.updated_at = stamp;

    let mut extras_old = extra_proxies;
    for proxy in &mut extras_old {
        proxy.created_at = stamp;
        proxy.updated_at = stamp;
    }
    let extras_new = extras_old.clone();

    let mut old_proxies = vec![proxy.clone()];
    old_proxies.extend(extras_old);
    let mut new_proxies = vec![proxy];
    new_proxies.extend(extras_new);

    let mut old_config = GatewayConfig {
        proxies: old_proxies,
        upstreams: vec![old_upstream],
        ..GatewayConfig::default()
    };
    let mut new_config = GatewayConfig {
        proxies: new_proxies,
        upstreams: vec![new_upstream],
        ..GatewayConfig::default()
    };
    old_config.normalize_fields();
    old_config.resolve_upstream_tls();
    new_config.normalize_fields();
    new_config.resolve_upstream_tls();
    (old_config, new_config)
}

#[tokio::test]
async fn update_config_republishes_routes_for_empty_delta_dr_fallback_change() {
    let (old_config, new_config) = projected_only_configs(
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(1_000),
                ..Default::default()
            });
        },
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(2_000),
                ..Default::default()
            });
        },
    );

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        delta.is_empty(),
        "fixture must keep ConfigDelta empty so the empty-delta publish path is exercised"
    );
    assert!(
        delta.modified_proxies.is_empty(),
        "DR-only edits must not manufacture a Proxy resource modification"
    );

    let (state, _handles) = new_proxy_state(old_config);
    assert_eq!(route_fallback_idle_ms(&state), Some(1_000));

    let outcome = state.update_config(new_config);
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert_eq!(
        route_fallback_idle_ms(&state),
        Some(2_000),
        "empty-delta DR projection change must swap the route-held Arc<Proxy> immediately"
    );
}

#[tokio::test]
async fn update_config_republishes_routes_for_empty_delta_dr_tls_change() {
    let (old_config, new_config) = projected_only_configs(
        |upstream| {
            upstream.backend_tls_sni = Some("old.backend.mesh.internal".to_string());
        },
        |upstream| {
            upstream.backend_tls_sni = Some("new.backend.mesh.internal".to_string());
        },
    );

    // TLS fields are serialized, so bumping content without advancing
    // `updated_at` is the same ConfigDelta-blind shape operators hit when a
    // DR projection lands without a proxy edit.
    let mut old = old_config;
    let mut new = new_config;
    // Force identical timestamps after projection so ConfigDelta stays empty
    // even though serialized TLS content differs — the production mesh
    // reconcile normally advances `updated_at`, but the route signal must not
    // depend on that alone.
    let stamp = old.upstreams[0].updated_at;
    new.upstreams[0].updated_at = stamp;
    new.upstreams[0].created_at = old.upstreams[0].created_at;
    old.resolve_upstream_tls();
    new.resolve_upstream_tls();
    // Re-run normalize so dispatch projections stay consistent with the TLS
    // resolve pass above.
    old.normalize_fields();
    new.normalize_fields();
    old.resolve_upstream_tls();
    new.resolve_upstream_tls();
    new.upstreams[0].updated_at = stamp;
    new.upstreams[0].created_at = old.upstreams[0].created_at;
    new.proxies[0].updated_at = old.proxies[0].updated_at;
    new.proxies[0].created_at = old.proxies[0].created_at;

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old, &new);
    assert!(
        delta.is_empty(),
        "TLS fixture must keep ConfigDelta empty (same resource timestamps)"
    );

    let (state, _handles) = new_proxy_state(old);
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("old.backend.mesh.internal")
    );

    assert_eq!(state.update_config(new), ConfigApplyOutcome::Applied);
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("new.backend.mesh.internal"),
        "DR TLS projection change must refresh route-held resolved_tls without a Proxy delta"
    );
}

#[tokio::test]
async fn update_config_removes_dr_fallback_and_restores_route_defaults() {
    let (with_fallback, without_fallback) = projected_only_configs(
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(4_000),
                ..Default::default()
            });
        },
        |_upstream| {},
    );

    let (state, _handles) = new_proxy_state(with_fallback);
    assert_eq!(route_fallback_idle_ms(&state), Some(4_000));

    assert_eq!(
        state.update_config(without_fallback),
        ConfigApplyOutcome::Applied
    );
    assert_eq!(
        route_fallback_idle_ms(&state),
        None,
        "DR removal must clear the route-held fallback projection back to defaults"
    );
}

#[tokio::test]
async fn update_config_dr_noop_and_repeated_reload_are_stable() {
    let stamp = Utc::now() - Duration::seconds(30);
    let prepared = prepared_with_dr_at(Some(destination_rule(Some(7_000), None)), stamp);
    let (state, _handles) = new_proxy_state(prepared.clone());
    assert_eq!(route_fallback_idle_ms(&state), Some(7_000));

    // Unchanged-config no-op: re-applying the same generation must not invent
    // a route rebuild requirement beyond what ArcSwap publish already did.
    let first = state.update_config(prepared.clone());
    assert!(
        matches!(
            first,
            ConfigApplyOutcome::Unchanged | ConfigApplyOutcome::Applied
        ),
        "identical candidate must be accepted; got {first:?}"
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(7_000));

    // Repeated reload with a real DR pool change then a second identical apply.
    let changed = prepared_with_dr_at(Some(destination_rule(Some(9_000), None)), stamp);
    assert_eq!(
        state.update_config(changed.clone()),
        ConfigApplyOutcome::Applied
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(9_000));

    let repeat = state.update_config(changed);
    assert!(
        matches!(
            repeat,
            ConfigApplyOutcome::Unchanged | ConfigApplyOutcome::Applied
        ),
        "repeated identical DR reload must stay accepted; got {repeat:?}"
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(9_000));
}

#[tokio::test]
async fn update_config_applies_mesh_dr_prepare_without_proxy_resource_edit() {
    // Live mesh prepare path: Services/VirtualServices (proxies) unchanged;
    // only DestinationRule pool + TLS projections change. No manufactured
    // Proxy `updated_at` bump — the invalidation signal must fire from the
    // projected fields alone (or the mesh-block / upstream timestamp delta
    // the mesh apply already produces).
    let stamp = Utc::now() - Duration::seconds(30);
    let initial = prepared_with_dr_at(
        Some(destination_rule(
            Some(1_500),
            Some("initial.reviews.mesh.internal"),
        )),
        stamp,
    );
    let updated = prepared_with_dr_at(
        Some(destination_rule(
            Some(3_500),
            Some("updated.reviews.mesh.internal"),
        )),
        stamp,
    );

    assert_eq!(
        initial
            .proxies
            .iter()
            .find(|proxy| proxy.id == "reviews-p")
            .expect("reviews proxy")
            .updated_at,
        updated
            .proxies
            .iter()
            .find(|proxy| proxy.id == "reviews-p")
            .expect("reviews proxy")
            .updated_at
    );

    let (state, _handles) = new_proxy_state(initial);
    assert_eq!(route_fallback_idle_ms(&state), Some(1_500));
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("initial.reviews.mesh.internal")
    );

    assert_eq!(state.update_config(updated), ConfigApplyOutcome::Applied);
    assert_eq!(route_fallback_idle_ms(&state), Some(3_500));
    assert_eq!(
        route_tls_sni(&state).as_deref(),
        Some("updated.reviews.mesh.internal"),
        "mesh DR-only prepare must refresh pool + TLS on the live route table without a Proxy edit"
    );
}

#[tokio::test]
async fn update_config_unrelated_mesh_policy_does_not_require_proxy_edit_for_dr() {
    // Pin the "no unrelated event" acceptance criterion: a DestinationRule
    // projection change is sufficient by itself. The prior generation already
    // carries a non-DR mesh block; swapping only the DR still republishes.
    let stamp = Utc::now() - Duration::seconds(30);
    let mut base = prepared_with_dr_at(Some(destination_rule(Some(2_200), None)), stamp);
    if let Some(mesh) = base.mesh.as_mut() {
        // Keep a stable non-DR mesh field so the candidate is not "mesh absent".
        mesh.istio_root_namespace = "istio-system".to_string();
    }
    let mut next = prepared_with_dr_at(Some(destination_rule(Some(8_800), None)), stamp);
    if let Some(mesh) = next.mesh.as_mut() {
        mesh.istio_root_namespace = "istio-system".to_string();
    }

    let (state, _handles) = new_proxy_state(base);
    let before = Arc::as_ptr(
        &state
            .router_cache
            .find_proxy(Some("reviews.example.com"), "/http")
            .expect("route")
            .proxy,
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(2_200));

    assert_eq!(state.update_config(next), ConfigApplyOutcome::Applied);
    let after = Arc::as_ptr(
        &state
            .router_cache
            .find_proxy(Some("reviews.example.com"), "/http")
            .expect("route")
            .proxy,
    );
    assert_ne!(
        before, after,
        "DR-only change must publish a fresh route-held Arc<Proxy>, not wait for an unrelated proxy event"
    );
    assert_eq!(route_fallback_idle_ms(&state), Some(8_800));
}

#[tokio::test]
async fn update_config_republishes_routes_for_empty_delta_per_port_projection_change() {
    let (old_config, new_config) = projected_only_configs(
        |upstream| {
            upstream.port_overrides.insert(
                8080,
                UpstreamPortOverride {
                    connect_timeout_ms: Some(1_000),
                    max_retries: Some(1),
                    locality_lb_setting: Some(UpstreamLocalityLbSetting {
                        enabled: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        },
        |upstream| {
            upstream.port_overrides.insert(
                8080,
                UpstreamPortOverride {
                    connect_timeout_ms: Some(2_500),
                    max_retries: Some(4),
                    locality_lb_setting: Some(UpstreamLocalityLbSetting {
                        enabled: false,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        },
    );

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        delta.is_empty(),
        "per-port DR projection fixture must keep ConfigDelta empty"
    );
    assert!(
        delta.modified_proxies.is_empty(),
        "per-port DR edits must not manufacture a Proxy resource modification"
    );

    let (state, _handles) = new_proxy_state(old_config);
    let before = route_port_override(&state, 8080).expect("old per-port override");
    assert_eq!(before.connect_timeout_ms, Some(1_000));
    assert_eq!(before.max_retries, Some(1));
    assert_eq!(
        before
            .locality_lb_setting
            .as_ref()
            .map(|setting| setting.enabled),
        Some(true)
    );

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);
    let after = route_port_override(&state, 8080).expect("new per-port override");
    assert_eq!(after.connect_timeout_ms, Some(2_500));
    assert_eq!(after.max_retries, Some(4));
    assert_eq!(
        after
            .locality_lb_setting
            .as_ref()
            .map(|setting| setting.enabled),
        Some(false),
        "empty-delta per-port timeout/retry/locality projections must refresh the live route"
    );
}

#[tokio::test]
async fn update_config_republishes_routes_for_empty_delta_retry_fallback_change() {
    let (old_config, new_config) = projected_only_configs(
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                max_retries: Some(2),
                http_idle_timeout_ms: Some(1_000),
                ..Default::default()
            });
        },
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                max_retries: Some(0),
                http_idle_timeout_ms: Some(1_000),
                ..Default::default()
            });
        },
    );

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(delta.is_empty());
    assert!(delta.modified_proxies.is_empty());

    let (state, _handles) = new_proxy_state(old_config);
    assert_eq!(route_fallback_max_retries(&state), Some(2));
    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);
    assert_eq!(
        route_fallback_max_retries(&state),
        Some(0),
        "empty-delta DR retry/pool fallback change must swap the route-held projection"
    );
}

#[tokio::test]
async fn update_config_dr_projection_does_not_mutate_unrelated_route_policy() {
    let (old_config, new_config) = projected_only_configs_with_extra_proxies(
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(1_000),
                ..Default::default()
            });
        },
        |upstream| {
            upstream.dispatch_port_override_fallback = Some(UpstreamPortOverride {
                http_idle_timeout_ms: Some(9_000),
                ..Default::default()
            });
        },
        vec![unrelated_http_proxy()],
    );

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        delta.is_empty(),
        "unrelated-route fixture must keep ConfigDelta empty"
    );
    assert!(
        delta.modified_proxies.is_empty(),
        "DR-only signaling must not invent Proxy modifications for any route"
    );

    let (state, _handles) = new_proxy_state(old_config);
    let unrelated_before = state
        .router_cache
        .find_proxy(Some("ratings.example.com"), "/ratings")
        .expect("unrelated route")
        .proxy
        .clone();
    assert!(unrelated_before.dispatch_port_override_fallback.is_none());
    assert_eq!(route_fallback_idle_ms(&state), Some(1_000));

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);
    assert_eq!(route_fallback_idle_ms(&state), Some(9_000));

    let unrelated_after = state
        .router_cache
        .find_proxy(Some("ratings.example.com"), "/ratings")
        .expect("unrelated route")
        .proxy
        .clone();
    assert!(
        unrelated_after.dispatch_port_override_fallback.is_none(),
        "DR projection rebuild must not invent policy on an unrelated route"
    );
    assert_eq!(unrelated_after.backend_host, unrelated_before.backend_host);
    assert_eq!(unrelated_after.backend_port, unrelated_before.backend_port);
    assert_eq!(unrelated_after.listen_path, unrelated_before.listen_path);
}

#[tokio::test]
async fn update_config_clears_empty_delta_per_port_projection_on_withdrawal() {
    let (with_override, without_override) = projected_only_configs(
        |upstream| {
            upstream.port_overrides.insert(
                8080,
                UpstreamPortOverride {
                    connect_timeout_ms: Some(3_000),
                    max_retries: Some(2),
                    ..Default::default()
                },
            );
        },
        |_upstream| {},
    );

    let (state, _handles) = new_proxy_state(with_override);
    assert!(route_port_override(&state, 8080).is_some());

    assert_eq!(
        state.update_config(without_override),
        ConfigApplyOutcome::Applied
    );
    assert!(
        route_port_override(&state, 8080).is_none(),
        "DR per-port withdrawal must clear stale route-held dispatch overrides"
    );
}

#[tokio::test]
async fn update_config_rebuilds_lb_for_projected_dr_change_with_unrelated_consumer_delta() {
    // Mixed publish: projected-only DestinationRule LB policy change (frozen
    // upstream timestamps → no upstream ConfigDelta membership) PLUS an
    // unrelated consumer addition that forces the non-empty incremental path.
    // Route rebuild alone is insufficient — LoadBalancerCache must observe the
    // new algorithm/hash/locality without inventing a Proxy/Upstream edit.
    let (mut old_config, mut new_config) = projected_only_configs(
        |upstream| {
            upstream.port_overrides.insert(
                8080,
                UpstreamPortOverride {
                    algorithm: Some(LoadBalancerAlgorithm::RoundRobin),
                    hash_on: Some("ip".to_string()),
                    locality_lb_setting: Some(UpstreamLocalityLbSetting {
                        enabled: true,
                        ..Default::default()
                    }),
                    connect_timeout_ms: Some(1_000),
                    ..Default::default()
                },
            );
        },
        |upstream| {
            upstream.port_overrides.insert(
                8080,
                UpstreamPortOverride {
                    algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
                    hash_on: Some("header:x-request-id".to_string()),
                    locality_lb_setting: Some(UpstreamLocalityLbSetting {
                        enabled: false,
                        ..Default::default()
                    }),
                    connect_timeout_ms: Some(2_500),
                    ..Default::default()
                },
            );
        },
    );

    new_config
        .consumers
        .push(unrelated_consumer("c-unrelated", "unrelated-user"));
    let unrelated = unrelated_upstream();
    old_config.upstreams.push(unrelated.clone());
    new_config.upstreams.push(unrelated);
    new_config.normalize_fields();

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        !delta.is_empty(),
        "unrelated consumer addition must force the non-empty incremental staging path"
    );
    assert_eq!(delta.added_consumers.len(), 1);
    assert!(
        delta.modified_proxies.is_empty(),
        "projected DR change must not invent a Proxy resource modification"
    );
    assert!(
        delta.modified_upstreams.is_empty()
            && delta.added_upstreams.is_empty()
            && delta.removed_upstream_ids.is_empty(),
        "fixture must keep upstream ConfigDelta membership empty so LB cannot \
         rely on build_delta_inner seeing an affected upstream"
    );

    old_config.normalize_fields();
    let (state, _handles) = new_proxy_state(old_config);
    let unrelated_before = state
        .load_balancer_cache
        .load()
        .get_balancer("default", "ratings-u")
        .expect("unrelated upstream balancer");
    assert_eq!(
        lb_effective_algorithm(&state, Some(8080)),
        LoadBalancerAlgorithm::RoundRobin
    );
    assert_eq!(lb_hash_on_for_port(&state, 8080), HashOnStrategy::Ip);
    let before_port = route_port_override(&state, 8080).expect("old per-port override");
    assert_eq!(
        before_port.algorithm,
        Some(LoadBalancerAlgorithm::RoundRobin)
    );
    assert_eq!(
        before_port
            .locality_lb_setting
            .as_ref()
            .map(|setting| setting.enabled),
        Some(true)
    );
    assert!(
        state
            .consumer_index
            .consumers()
            .iter()
            .all(|consumer| consumer.username != "unrelated-user")
    );

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);

    assert_eq!(
        lb_effective_algorithm(&state, Some(8080)),
        LoadBalancerAlgorithm::ConsistentHashing,
        "mixed-delta projected DR change must full-rebuild LB so the published \
         epoch observes the new algorithm"
    );
    assert_eq!(
        lb_hash_on_for_port(&state, 8080),
        HashOnStrategy::Header("x-request-id".to_string()),
        "published LB must observe the new per-port hash_on policy"
    );
    let after_port = route_port_override(&state, 8080).expect("new per-port override");
    assert_eq!(
        after_port.algorithm,
        Some(LoadBalancerAlgorithm::ConsistentHashing)
    );
    assert_eq!(after_port.connect_timeout_ms, Some(2_500));
    assert_eq!(
        after_port
            .locality_lb_setting
            .as_ref()
            .map(|setting| setting.enabled),
        Some(false),
        "route-held locality projection must refresh atomically with the LB"
    );
    assert!(
        state
            .consumer_index
            .consumers()
            .iter()
            .any(|consumer| consumer.username == "unrelated-user"),
        "unrelated consumer delta must still publish into the consumer index"
    );
    let unrelated_after = state
        .load_balancer_cache
        .load()
        .get_balancer("default", "ratings-u")
        .expect("unrelated upstream balancer after projected DR update");
    assert!(
        Arc::ptr_eq(&unrelated_before, &unrelated_after),
        "a projected DR edit must preserve unrelated RR/WRR/latency state"
    );
}

#[tokio::test]
async fn update_config_withdraws_projected_lb_policy_with_unrelated_consumer_delta() {
    // Withdrawal twin: clearing DR-derived per-port LB policy while an
    // unrelated consumer lands must restore the upstream default algorithm on
    // the published LB (not leave the old override live under a non-empty delta).
    let (mut old_config, mut new_config) = projected_only_configs(
        |upstream| {
            upstream.port_overrides.insert(
                8080,
                UpstreamPortOverride {
                    algorithm: Some(LoadBalancerAlgorithm::ConsistentHashing),
                    hash_on: Some("header:x-user".to_string()),
                    locality_lb_setting: Some(UpstreamLocalityLbSetting {
                        enabled: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
        },
        |_upstream| {},
    );

    new_config
        .consumers
        .push(unrelated_consumer("c-withdraw", "withdraw-user"));
    new_config.normalize_fields();

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(!delta.is_empty());
    assert!(delta.modified_proxies.is_empty());
    assert!(
        delta.modified_upstreams.is_empty()
            && delta.added_upstreams.is_empty()
            && delta.removed_upstream_ids.is_empty()
    );

    old_config.normalize_fields();
    let (state, _handles) = new_proxy_state(old_config);
    assert_eq!(
        lb_effective_algorithm(&state, Some(8080)),
        LoadBalancerAlgorithm::ConsistentHashing
    );
    assert!(route_port_override(&state, 8080).is_some());

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);
    assert_eq!(
        lb_effective_algorithm(&state, Some(8080)),
        LoadBalancerAlgorithm::RoundRobin,
        "projected LB policy withdrawal under a mixed delta must restore the \
         upstream default algorithm on the published LB"
    );
    assert!(
        route_port_override(&state, 8080).is_none(),
        "route-held per-port override must clear on withdrawal"
    );
    assert!(
        state
            .consumer_index
            .consumers()
            .iter()
            .any(|consumer| consumer.username == "withdraw-user")
    );
}

#[tokio::test]
async fn ordinary_proxy_edit_preserves_unaffected_load_balancer_snapshot() {
    let old_config = prepared_with_dr(None);
    let mut new_config = old_config.clone();
    let proxy = new_config
        .proxies
        .iter_mut()
        .find(|proxy| proxy.id == "reviews-p")
        .expect("reviews proxy");
    proxy.backend_read_timeout_ms = 7_500;
    proxy.updated_at += Duration::seconds(1);
    new_config.normalize_fields();

    let (state, _handles) = new_proxy_state(old_config);
    let before = Arc::clone(&*state.load_balancer_cache.load());

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);

    let after = Arc::clone(&*state.load_balancer_cache.load());
    assert!(
        Arc::ptr_eq(&before, &after),
        "an ordinary route-only proxy edit must not full-rebuild and reset every load balancer"
    );
}

#[tokio::test]
async fn empty_delta_same_timestamp_upstream_target_change_republishes_load_balancer() {
    let old_config = prepared_with_dr(None);
    let mut new_config = old_config.clone();
    let upstream = new_config
        .upstreams
        .iter_mut()
        .find(|upstream| upstream.id == "reviews-u")
        .expect("reviews upstream");
    let unchanged_timestamp = upstream.updated_at;
    upstream.targets[0].host = "reviews-v2.default.svc.cluster.local".to_string();
    upstream.targets[0].port = 9080;
    assert_eq!(upstream.updated_at, unchanged_timestamp);
    new_config.normalize_fields();

    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        delta.is_empty(),
        "fixture must exercise the timestamp-neutral empty-delta publish path"
    );

    let (state, _handles) = new_proxy_state(old_config);
    let before = state.load_balancer_cache.load();
    let before_upstream = LoadBalancerCache::get_upstream_from(&before, "default", "reviews-u")
        .expect("old reviews upstream");
    assert_eq!(
        before_upstream.targets[0].host,
        "reviews.default.svc.cluster.local"
    );
    drop(before);

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);

    let after = state.load_balancer_cache.load();
    let after_upstream = LoadBalancerCache::get_upstream_from(&after, "default", "reviews-u")
        .expect("updated reviews upstream");
    assert_eq!(
        (
            after_upstream.targets[0].host.as_str(),
            after_upstream.targets[0].port,
        ),
        ("reviews-v2.default.svc.cluster.local", 9080),
        "an upstream content change hidden from timestamp-based ConfigDelta must still replace the affected balancer"
    );
}

#[tokio::test]
async fn empty_delta_dr_rebuild_preserves_live_service_discovery_targets() {
    let stamp = Utc::now() - Duration::seconds(30);
    let old_config = prepared_mesh_sd_with_dr(stamp, 1_000);
    let new_config = prepared_mesh_sd_with_dr(stamp, 9_000);
    let delta = ferrum_edge::config_delta::ConfigDelta::compute(&old_config, &new_config);
    assert!(
        delta.is_empty(),
        "fixture must exercise the timestamp-neutral out-of-band publish path"
    );

    let (state, _handles) = new_proxy_state(old_config);
    state.start_service_discovery(None);

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let snapshot = state.load_balancer_cache.load();
            let live = LoadBalancerCache::get_upstream_from(&snapshot, "default", "reviews-u");
            let discovered = live.is_some_and(|upstream| {
                upstream.targets.len() == 1
                    && upstream.targets[0].host == "10.0.0.9"
                    && upstream.targets[0].port == 8080
            });
            if discovered {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mesh service discovery should publish its first target set");

    assert_eq!(state.update_config(new_config), ConfigApplyOutcome::Applied);
    assert_eq!(route_fallback_idle_ms(&state), Some(9_000));
    let after = state.load_balancer_cache.load();
    let upstream = LoadBalancerCache::get_upstream_from(&after, "default", "reviews-u")
        .expect("reviews upstream after DR rebuild");
    assert_eq!(
        (upstream.targets[0].host.as_str(), upstream.targets[0].port),
        ("10.0.0.9", 8080),
        "a DR-only policy rebuild must not roll back the live discovered target set to authored static targets"
    );
}
