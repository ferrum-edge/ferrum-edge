//! Authenticated `/metrics` exposition for `__mesh_bpf_metrics` (#2217).
//!
//! Covers the production scrape path (seeded shared BPF state → JWT-gated
//! `GET /metrics` → `ferrum_mesh_bpf_*` families) and plugin-cache reload
//! reconstruction (prefix/state replacement, removal, zero-state, no
//! duplicate exposition).

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::PluginCache;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::ebpf::bpf_metrics::BpfMetricsState;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::plugins::mesh::bpf_metrics::{DEFAULT_METRIC_PREFIX, PLUGIN_NAME};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

const JWT_SECRET: &str = "mesh-bpf-metrics-scrape-test-secret-key-00";
const JWT_ISSUER: &str = "ferrum-edge-mesh-bpf-metrics-test";
const TEST_PLUGIN_ID: &str = "mesh-bpf-metrics-scrape-test";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "mesh-bpf-metrics-test",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("encode admin JWT")
}

fn bpf_metrics_plugin_config(prefix: Option<&str>) -> PluginConfig {
    let config = match prefix {
        Some(prefix) => json!({ "prefix": prefix }),
        None => json!({}),
    };
    PluginConfig {
        id: TEST_PLUGIN_ID.to_string(),
        plugin_name: PLUGIN_NAME.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn gateway_with_bpf_metrics(prefix: Option<&str>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        plugin_configs: vec![bpf_metrics_plugin_config(prefix)],
        ..Default::default()
    }
}

fn empty_gateway(version: &str) -> GatewayConfig {
    GatewayConfig {
        version: version.to_string(),
        loaded_at: Utc::now(),
        ..Default::default()
    }
}

fn admin_state_with_proxy(proxy_state: ProxyState) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        proxy_state: Some(proxy_state),
        cached_config: None,
        mode: "test".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: Some(Arc::new(AtomicBool::new(true))),
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse bind addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind admin listener");
    let actual = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{actual}"), shutdown_tx)
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn assert_single_tcp_events_family(body: &str, prefix: &str) {
    assert_eq!(
        count_occurrences(body, &format!("# TYPE {prefix}_tcp_events_total counter")),
        1,
        "{prefix}_tcp_events_total TYPE line must appear exactly once:\n{body}"
    );
}

#[test]
fn priority_override_preserves_mesh_bpf_exporter_capability() {
    let mut cfg = gateway_with_bpf_metrics(Some("priority_bpf"));
    cfg.plugin_configs[0].priority_override = Some(1234);
    let cache = PluginCache::with_http_client(&cfg, PluginHttpClient::default())
        .expect("cache with priority-overridden bpf metrics");
    let exporter = cache
        .mesh_bpf_metrics_exporter()
        .expect("priority wrapper must forward the exporter capability");
    assert_eq!(exporter.prefix(), "priority_bpf");
    assert_single_tcp_events_family(&exporter.render_prometheus(), "priority_bpf");
}

#[tokio::test]
async fn authenticated_metrics_includes_seeded_mesh_bpf_families() {
    let state = BpfMetricsState::new();
    state.record_connect();
    state.record_accept_established();
    state.record_srtt_sample(250);

    let cfg = gateway_with_bpf_metrics(None);
    let dns_cache = DnsCache::new(DnsConfig::default());
    let (proxy_state, _handles) = ProxyState::new_with_bpf_metrics(
        cfg,
        dns_cache,
        EnvConfig::default(),
        None,
        None,
        Some(state.clone()),
    )
    .expect("proxy state with bpf metrics");

    let (base, shutdown) = start_admin(admin_state_with_proxy(proxy_state)).await;
    let client = reqwest::Client::new();

    let unauth = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .expect("unauth /metrics");
    assert_eq!(
        unauth.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "/metrics must stay authenticated"
    );

    let resp = client
        .get(format!("{base}/metrics"))
        .bearer_auth(admin_token())
        .send()
        .await
        .expect("auth /metrics");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.expect("metrics body");

    assert!(
        body.contains(&format!(
            "{DEFAULT_METRIC_PREFIX}_tcp_events_total{{event=\"connect\"}} 1"
        )),
        "seeded connect counter missing from /metrics:\n{body}"
    );
    assert!(
        body.contains(&format!(
            "{DEFAULT_METRIC_PREFIX}_tcp_events_total{{event=\"accept_established\"}} 1"
        )),
        "seeded accept counter missing from /metrics:\n{body}"
    );
    assert!(
        body.contains(&format!(
            "{DEFAULT_METRIC_PREFIX}_srtt_microseconds_sum 250"
        )),
        "seeded srtt sum missing from /metrics:\n{body}"
    );
    assert_single_tcp_events_family(&body, DEFAULT_METRIC_PREFIX);

    let _ = shutdown.send(true);
}

#[tokio::test]
async fn authenticated_metrics_omits_mesh_bpf_when_plugin_absent() {
    let cfg = empty_gateway("1");
    let dns_cache = DnsCache::new(DnsConfig::default());
    let (proxy_state, _handles) =
        ProxyState::new(cfg, dns_cache, EnvConfig::default(), None, None).expect("proxy state");

    let (base, shutdown) = start_admin(admin_state_with_proxy(proxy_state)).await;
    let body = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .bearer_auth(admin_token())
        .send()
        .await
        .expect("auth /metrics")
        .text()
        .await
        .expect("metrics body");

    assert!(
        !body.contains("ferrum_mesh_bpf_"),
        "inactive plugin must emit nothing from the bpf renderer:\n{body}"
    );

    let _ = shutdown.send(true);
}

#[tokio::test]
async fn plugin_cache_reload_switches_exporter_atomically() {
    let state = BpfMetricsState::new();
    state.record_connect();

    let dns_cache = DnsCache::new(DnsConfig::default());
    let (proxy_state, _handles) = ProxyState::new_with_bpf_metrics(
        gateway_with_bpf_metrics(None),
        dns_cache,
        EnvConfig::default(),
        None,
        None,
        Some(state.clone()),
    )
    .expect("proxy state with bpf metrics");

    let exporter = proxy_state
        .plugin_cache
        .mesh_bpf_metrics_exporter()
        .expect("exporter present after initial build");
    assert_eq!(exporter.prefix(), DEFAULT_METRIC_PREFIX);
    let rendered = exporter.render_prometheus();
    assert!(rendered.contains(&format!(
        "{DEFAULT_METRIC_PREFIX}_tcp_events_total{{event=\"connect\"}} 1"
    )));
    assert_single_tcp_events_family(&rendered, DEFAULT_METRIC_PREFIX);

    // Prefix replacement keeps the shared BPF state Arc and emits exactly once.
    let mut custom = gateway_with_bpf_metrics(Some("tenantA_bpf"));
    custom.version = "2".to_string();
    assert_eq!(
        proxy_state.update_config(custom),
        ConfigApplyOutcome::Applied
    );
    let exporter = proxy_state
        .plugin_cache
        .mesh_bpf_metrics_exporter()
        .expect("exporter present after prefix replacement");
    assert_eq!(exporter.prefix(), "tenantA_bpf");
    let rendered = exporter.render_prometheus();
    assert!(rendered.contains("tenantA_bpf_tcp_events_total{event=\"connect\"} 1"));
    assert!(!rendered.contains("ferrum_mesh_bpf_tcp_events_total"));
    assert_single_tcp_events_family(&rendered, "tenantA_bpf");

    // Removal clears the precomputed exporter — stale instance must not linger.
    assert_eq!(
        proxy_state.update_config(empty_gateway("3")),
        ConfigApplyOutcome::Applied
    );
    assert!(
        proxy_state
            .plugin_cache
            .mesh_bpf_metrics_exporter()
            .is_none(),
        "removed plugin must clear the precomputed exporter"
    );

    // Re-add without an attached BPF state on a fresh cache → stable zeros.
    let zero_cache =
        PluginCache::with_http_client(&gateway_with_bpf_metrics(None), PluginHttpClient::default())
            .expect("cache with zero-state bpf metrics");
    let zero_body = zero_cache
        .mesh_bpf_metrics_exporter()
        .expect("zero-state exporter")
        .render_prometheus();
    assert!(zero_body.contains(&format!(
        "{DEFAULT_METRIC_PREFIX}_tcp_events_total{{event=\"connect\"}} 0"
    )));
    assert_single_tcp_events_family(&zero_body, DEFAULT_METRIC_PREFIX);

    // Distinct shared-state attachment replaces prior counters.
    let state_b = BpfMetricsState::new();
    state_b.record_accept_established();
    let cache_b = PluginCache::with_http_client(
        &gateway_with_bpf_metrics(None),
        PluginHttpClient::default().with_bpf_metrics_state(state_b),
    )
    .expect("cache with replacement state");
    let rendered = cache_b
        .mesh_bpf_metrics_exporter()
        .expect("exporter")
        .render_prometheus();
    assert!(rendered.contains(&format!(
        "{DEFAULT_METRIC_PREFIX}_tcp_events_total{{event=\"accept_established\"}} 1"
    )));
    assert!(rendered.contains(&format!(
        "{DEFAULT_METRIC_PREFIX}_tcp_events_total{{event=\"connect\"}} 0"
    )));
    assert_single_tcp_events_family(&rendered, DEFAULT_METRIC_PREFIX);
}
