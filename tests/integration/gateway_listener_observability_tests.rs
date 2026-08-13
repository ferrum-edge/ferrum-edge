//! Dynamic Gateway API listener bind failures reach production observability
//! (issue #3810).
//!
//! The manager already refuses traffic fail closed for an unbindable listener
//! port, keeps every healthy listener serving, and retries forever. These tests
//! cover the consumer side of that state end to end:
//!
//! - a real occupied TCP port produces a bounded active failure while its
//!   sibling listener keeps serving,
//! - releasing the port clears the failure on the next reconcile,
//! - authenticated `/health` exposes the detail and unauthenticated `/health`
//!   exposes neither the port nor the error,
//! - the optional readiness contract degrades readiness without claiming the
//!   process is unavailable, and never affects `/live`,
//! - file, database, and data-plane modes wire the same status handle.
//!
//! Accept-loop death and stale-generation fencing are private-state behaviors
//! covered where they can be driven deterministically: the inline supervision
//! test in `src/proxy/gateway_listener.rs` and
//! `tests/unit/gateway_core/gateway_listener_status_tests.rs`.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use ferrum_edge::proxy::gateway_listener::{GatewayListenerManager, GatewayListenerTls};
use ferrum_edge::proxy::gateway_listener_status::{
    GatewayListenerFailureCategory, GatewayListenerFailureObservation, GatewayListenerProtocolHalf,
    GatewayListenerStatus,
};
use serde_json::Value;

const METRICS_TOKEN: &str = "gateway-listener-observability-metrics-token";

fn port_scoped_config(ports: &[u16]) -> GatewayConfig {
    let proxies: Vec<ferrum_edge::config::types::Proxy> = ports
        .iter()
        .enumerate()
        .map(|(index, port)| {
            serde_json::from_value(serde_json::json!({
                "id": format!("gw-{index}"),
                "hosts": ["app.example.com"],
                "listen_path": format!("/api-{index}"),
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 1,
                "listen_port": port,
            }))
            .expect("port-scoped proxy deserializes")
        })
        .collect();
    let mut config = GatewayConfig {
        proxies,
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    config
}

fn test_state(config: GatewayConfig) -> ProxyState {
    let env = EnvConfig {
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        ..EnvConfig::default()
    };
    ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
        .expect("proxy state")
        .0
}

fn is_printable_ascii(text: &str) -> bool {
    text.chars().all(|ch| ch == ' ' || ch.is_ascii_graphic())
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

/// An occupied Gateway listener port must become a bounded, structured active
/// failure — while the sibling listener on the same generation keeps serving
/// and the process keeps running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_occupied_port_is_surfaced_while_the_sibling_listener_keeps_serving() {
    let healthy_port = free_port().await;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("occupy a port before the gateway can bind it");
    let occupied_port = occupied.local_addr().expect("addr").port();
    assert_ne!(healthy_port, occupied_port);

    let status = Arc::new(GatewayListenerStatus::new());
    let manager = GatewayListenerManager::new(
        test_state(port_scoped_config(&[healthy_port, occupied_port])),
        std::net::IpAddr::from([127, 0, 0, 1]),
        GatewayListenerTls::default(),
    )
    .with_status(status.clone());

    manager.reconcile().await;

    assert_eq!(
        manager.active_ports().await,
        vec![healthy_port],
        "only the bindable listener may be live"
    );

    let snapshot = status.snapshot();
    assert_eq!(snapshot.desired_listeners, 2);
    assert_eq!(snapshot.active_listeners, 1);
    assert_eq!(snapshot.failed_ports, 1);
    assert_eq!(snapshot.active_failures, 1);
    assert!(!snapshot.truncated);
    assert!(snapshot.degraded());

    let entry = &snapshot.failures[0];
    assert_eq!(entry.port, occupied_port);
    assert_eq!(entry.protocol, GatewayListenerProtocolHalf::Tcp);
    assert_eq!(entry.category, GatewayListenerFailureCategory::BindFailed);
    assert!(!entry.detail.is_empty());
    assert!(is_printable_ascii(&entry.detail), "{}", entry.detail);

    // Releasing the port lets the very next reconcile bind it: no restart, no
    // config reload, and the status clears with a counted recovery.
    drop(occupied);
    // Give the kernel a moment to release the listening socket.
    for _ in 0..40 {
        manager.reconcile().await;
        if !status.snapshot().degraded() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let recovered = status.snapshot();
    assert!(
        !recovered.degraded(),
        "a released port must clear on the next retry: {recovered:?}"
    );
    assert_eq!(recovered.active_listeners, 2);
    let mut active = manager.active_ports().await;
    active.sort_unstable();
    let mut expected = vec![healthy_port, occupied_port];
    expected.sort_unstable();
    assert_eq!(active, expected);
    assert_eq!(
        status
            .cumulative()
            .recoveries_total
            .iter()
            .find(|series| {
                series.protocol == GatewayListenerProtocolHalf::Tcp
                    && series.category == GatewayListenerFailureCategory::BindFailed
            })
            .map(|series| series.value),
        Some(1)
    );

    manager.shutdown_all().await;
}

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: "gateway-listener-observability-test-secret-000".to_string(),
        issuer: "ferrum-edge-gateway-listener-test".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_state(
    status: Arc<GatewayListenerStatus>,
    gateway_listener_failure_fails_readiness: bool,
) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Arc::new(MetricsAuthPolicy {
            allowed_cidrs: TrustedProxies::none(),
            bearer_token: Some(METRICS_TOKEN.to_string()),
        }),
        proxy_state: None,
        cached_config: None,
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: Some(status),
        gateway_listener_failure_fails_readiness,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
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
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let addr = listener.local_addr().expect("admin addr");
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
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

async fn get(base: &str, path: &str, bearer: Option<&str>) -> (u16, Value) {
    let client = reqwest::Client::new();
    let mut request = client.get(format!("{base}{path}"));
    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = request.send().await.expect("admin request");
    let status = response.status().as_u16();
    let body: Value = response.json().await.expect("json body");
    (status, body)
}

fn publish_one_failure(status: &GatewayListenerStatus) {
    assert!(status.publish(
        3,
        2,
        1,
        vec![GatewayListenerFailureObservation::new(
            18_443,
            GatewayListenerProtocolHalf::Tcp,
            GatewayListenerFailureCategory::BindFailed,
            "port 18443 bind failed: Address already in use (os error 48)",
        )],
        1_000,
    ));
}

/// The authenticated tier carries the bounded detail; the unauthenticated tier
/// carries neither the port, the error, nor any listener count — only the
/// coarse `degraded` status a probe or alert can select on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_health_exposes_detail_and_unauthenticated_health_stays_minimal() {
    let status = Arc::new(GatewayListenerStatus::new());
    publish_one_failure(&status);
    let (base, shutdown) = start_admin(admin_state(status, false)).await;

    let (code, anonymous) = get(&base, "/health", None).await;
    assert_eq!(
        code, 200,
        "a recoverable partial listener outage must not withdraw the replica by default"
    );
    assert_eq!(anonymous["status"], "degraded");
    assert_eq!(anonymous["ready"], true);
    let object = anonymous.as_object().expect("object body");
    assert_eq!(
        object.len(),
        2,
        "the unauthenticated body must stay exactly status+ready: {anonymous}"
    );
    let rendered = anonymous.to_string();
    for forbidden in ["18443", "gateway_listeners", "os error", "bind failed"] {
        assert!(
            !rendered.contains(forbidden),
            "unauthenticated health leaked {forbidden:?}: {rendered}"
        );
    }

    let (code, detailed) = get(&base, "/health", Some(METRICS_TOKEN)).await;
    assert_eq!(code, 200);
    assert_eq!(detailed["status"], "degraded");
    assert_eq!(detailed["ready"], true);
    let listeners = &detailed["gateway_listeners"];
    assert_eq!(listeners["desired_listeners"], 2);
    assert_eq!(listeners["active_listeners"], 1);
    assert_eq!(listeners["failed_ports"], 1);
    assert_eq!(listeners["active_failures"], 1);
    assert_eq!(listeners["truncated"], false);
    assert_eq!(listeners["overflowed"], false);
    assert_eq!(listeners["config_generation"], 3);
    let entry = &listeners["failures"][0];
    assert_eq!(entry["port"], 18_443);
    assert_eq!(entry["protocol"], "tcp");
    assert_eq!(entry["category"], "bind_failed");
    assert_eq!(entry["origin"], "runtime");
    assert_eq!(entry["observations"], 1);

    // Liveness is never affected by a partial listener outage.
    let (code, live) = get(&base, "/live", None).await;
    assert_eq!(code, 200);
    assert_eq!(live, serde_json::json!({"status": "ok"}));

    let _ = shutdown.send(true);
}

/// The opt-in readiness contract degrades readiness but keeps the status
/// `degraded` — a recoverable partial outage must never be reported as a lost
/// dependency (`unavailable`), and `/live` must stay healthy so the container
/// is not restarted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opt_in_readiness_degrades_without_claiming_the_process_is_unavailable() {
    let status = Arc::new(GatewayListenerStatus::new());
    publish_one_failure(&status);
    let (base, shutdown) = start_admin(admin_state(status.clone(), true)).await;

    let (code, body) = get(&base, "/health", None).await;
    assert_eq!(code, 503);
    assert_eq!(body["ready"], false);
    assert_eq!(
        body["status"], "degraded",
        "a recoverable partial outage is not `unavailable`"
    );

    let (code, live) = get(&base, "/live", None).await;
    assert_eq!(code, 200, "liveness must stay healthy: {live}");

    // Recovery restores readiness with no restart and no config reload.
    assert!(status.publish(3, 2, 2, Vec::new(), 2_000));
    let (code, body) = get(&base, "/health", None).await;
    assert_eq!(code, 200);
    assert_eq!(body["ready"], true);
    assert_eq!(body["status"], "ok");

    let _ = shutdown.send(true);
}

/// File, database, and data-plane modes are the three modes that bind dynamic
/// Gateway listener ports. Each must construct the shared status, hand it to
/// the manager, publish it on the process `/metrics` slot, and install it on
/// `AdminState` — otherwise that mode's operators silently lose the signal.
///
/// A source-level parity gate rather than three live mode harnesses: database
/// and data-plane startup need a database and a control plane respectively, and
/// the failure this guards against is a missing wire, not a runtime behavior
/// difference.
#[test]
fn file_database_and_data_plane_modes_wire_the_same_listener_status() {
    const SOURCES: &[(&str, &str)] = &[
        ("file", include_str!("../../src/modes/file.rs")),
        ("database", include_str!("../../src/modes/database.rs")),
        ("data_plane", include_str!("../../src/modes/data_plane.rs")),
    ];
    for (mode, source) in SOURCES {
        for required in [
            "gateway_listener_status::GatewayListenerStatus::new()",
            "gateway_listener_status::install_for_metrics(&gateway_listener_status)",
            ".with_status(gateway_listener_status.clone())",
            "gateway_listener_status: Some(gateway_listener_status.clone())",
            "gateway_listener_failure_fails_readiness: env_config",
        ] {
            assert!(
                source.contains(required),
                "{mode} mode is missing the dynamic Gateway listener observability wiring: \
                 {required}"
            );
        }
    }
}
