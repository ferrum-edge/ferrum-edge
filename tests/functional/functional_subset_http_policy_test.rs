//! Live traffic-path acceptance for selected-subset DestinationRule HTTP policy.
//!
//! Covers the three child mechanisms on a real in-process Ferrum gateway:
//! selected-subset `h2UpgradePolicy` (ALPN/protocol observable at the backend),
//! `maxRetries` attempt capping, and subset-isolated `http1MaxPendingRequests`
//! admission/permit release — including sibling/unmatched non-leakage.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_subset_http_policy -- --ignored --nocapture`

use crate::scaffolding::{
    H2Step, MatchHeaders, ScriptedH2Backend, ScriptedTlsBackend, TcpStep, TestCa, TlsConfig,
    reserve_port,
};

use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::{GatewayConfig, H2UpgradePolicy};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::ServeOptions;
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use ferrum_edge::proxy::build_backend_url_with_target;
use http::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

const NS: &str = "ferrum";
const UPSTREAM_ID: &str = "subset-http-upstream";
const JWT_SECRET: &str = "ferrum-edge-subset-http-policy-secret-0000";
const JWT_ISSUER: &str = "ferrum-edge-subset-http-policy";

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_subset_http_h2_upgrade_policy_is_observable_at_backend() {
    let ca = TestCa::new("subset-http-h2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let h1_res = reserve_port().await.expect("h1 backend port");
    let h2_res = reserve_port().await.expect("h2 backend port");
    let h1_port = h1_res.port;
    let h2_port = h2_res.port;

    // v1 DoNotUpgrade must land on this H1-speaking TLS fixture with http/1.1 ALPN.
    let h1_backend = ScriptedTlsBackend::builder(
        h1_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn h1 tls backend");

    // v2 Upgrade must negotiate H2 against this H2-only TLS fixture. Default
    // nonzero body limits keep this request on reqwest (not direct-H2); the
    // BuiltRustls client must therefore advertise [h2, http/1.1] so ALPN can
    // select h2 — empty ALPN stays on H1 and hangs/502s against H2-only.
    let h2_backend = ScriptedH2Backend::builder_tls(h2_res.into_listener(), &cert, &key)
        .expect("h2 tls builder")
        .repeat_script(true)
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "text/plain".into()),
        ]))
        .step(H2Step::RespondData {
            data: bytes::Bytes::from_static(b"ok"),
            end_stream: true,
        })
        .spawn()
        .expect("spawn h2 tls backend");

    let gateway = start_subset_gateway(
        subset_https_dual_backend_config(h1_port, h2_port),
        ExpectedSubsetPreparation {
            v1_h2_policy: H2UpgradePolicy::DoNotUpgrade,
            v2_h2_policy: H2UpgradePolicy::Upgrade,
            v1_port: h1_port,
            v2_port: h2_port,
            backend_scheme: "https",
            verify_server_cert: false,
        },
    )
    .await
    .expect("start subset h2 gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    let v1 = timeout(
        Duration::from_secs(10),
        client
            .get(format!("http://127.0.0.1:{}/v1/probe", gateway.http_port))
            .send(),
    )
    .await
    .expect("v1 request timed out")
    .expect("v1 request");
    assert_eq!(v1.status(), StatusCode::OK, "v1 DoNotUpgrade must succeed");
    // Successful completion already proves the H1 handshake/stream finished.
    assert!(
        h1_backend.handshakes_completed() >= 1,
        "v1 success must have completed an H1 TLS handshake"
    );
    let v1_alpn = h1_backend.last_alpn().await;
    assert_eq!(
        v1_alpn.as_deref(),
        Some(b"http/1.1".as_slice()),
        "selected subset v1 DoNotUpgrade must force HTTP/1.1 ALPN; got {v1_alpn:?}"
    );
    assert_eq!(
        h2_backend.accepted_connections(),
        0,
        "v1 traffic must not leak onto the H2-only sibling backend"
    );

    let v2 = timeout(
        Duration::from_secs(10),
        client
            .get(format!("http://127.0.0.1:{}/v2/probe", gateway.http_port))
            .send(),
    )
    .await
    .expect("v2 request timed out")
    .expect("v2 request");
    assert_eq!(
        v2.status(),
        StatusCode::OK,
        "v2 Upgrade must succeed over H2"
    );
    assert!(
        h2_backend.handshakes_completed() >= 1,
        "v2 success must have completed an H2 TLS handshake"
    );
    assert!(
        !h2_backend.received_streams().await.is_empty(),
        "selected subset v2 Upgrade must deliver an HTTP/2 stream to the backend"
    );

    gateway.shutdown().await;
    drop(h1_backend);
    drop(h2_backend);
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_subset_http_max_retries_caps_live_attempts() {
    // v1 (cap 1): two 503s. unmatched (top-level cap 5): three 503s then 200.
    let (backend_port, hits, shutdown_tx, backend_task) = spawn_status_script_backend(&[
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::OK,
    ])
    .await;

    let gateway = start_subset_gateway(
        subset_http_retry_config(backend_port),
        ExpectedSubsetPreparation {
            v1_h2_policy: H2UpgradePolicy::DoNotUpgrade,
            v2_h2_policy: H2UpgradePolicy::DoNotUpgrade,
            v1_port: backend_port,
            v2_port: backend_port,
            backend_scheme: "http",
            verify_server_cert: true,
        },
    )
    .await
    .expect("start subset retry gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http client");

    let v1 = timeout(
        Duration::from_secs(15),
        client
            .get(format!("http://127.0.0.1:{}/v1/retry", gateway.http_port))
            .send(),
    )
    .await
    .expect("v1 retry timed out")
    .expect("v1 retry request");
    // Subset v1 caps maxRetries to 1 → exactly two attempts; both 503 under the
    // script so the client sees the final failure rather than recovering.
    assert_eq!(
        v1.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "v1 capped retries must exhaust after the subset cap"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "selected subset maxRetries=1 must allow exactly 1 initial + 1 retry"
    );

    hits.store(0, Ordering::SeqCst);
    let unmatched = timeout(
        Duration::from_secs(15),
        client
            .get(format!(
                "http://127.0.0.1:{}/unmatched/retry",
                gateway.http_port
            ))
            .send(),
    )
    .await
    .expect("unmatched retry timed out")
    .expect("unmatched retry request");
    assert_eq!(
        unmatched.status(),
        StatusCode::OK,
        "unmatched top-level maxRetries=5 must recover within the larger budget"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        4,
        "unmatched must not inherit the v1 subset cap of 1 (expects 3 failures + recovery)"
    );

    let _ = shutdown_tx.send(true);
    gateway.shutdown().await;
    match timeout(Duration::from_secs(5), backend_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => panic!("status-script backend failed: {err}"),
        Ok(Err(join_err)) => panic!("status-script backend panicked: {join_err}"),
        Err(_) => panic!("status-script backend did not exit after shutdown"),
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn functional_subset_http1_pending_admission_is_subset_isolated() {
    let (backend_port, hits, first_hit_rx, release, shutdown_tx, backend_task) =
        spawn_holding_backend().await;
    let gateway = start_subset_gateway(
        subset_http_pending_config(backend_port),
        ExpectedSubsetPreparation {
            v1_h2_policy: H2UpgradePolicy::DoNotUpgrade,
            v2_h2_policy: H2UpgradePolicy::DoNotUpgrade,
            v1_port: backend_port,
            v2_port: backend_port,
            backend_scheme: "http",
            verify_server_cert: true,
        },
    )
    .await
    .expect("start subset pending gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_max_idle_per_host(0)
        .build()
        .expect("http client");

    let hold_url = format!("http://127.0.0.1:{}/v1/hold", gateway.http_port);
    let hold_client = client.clone();
    let hold = tokio::spawn(async move {
        timeout(Duration::from_secs(15), hold_client.get(hold_url).send())
            .await
            .expect("held v1 request timed out")
            .expect("held v1 request")
    });
    timeout(Duration::from_secs(10), first_hit_rx)
        .await
        .expect("first held backend hit timed out")
        .expect("first-hit channel closed");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "first v1 request must be held at the backend before shed/sibling probes"
    );

    let shed = timeout(
        Duration::from_secs(10),
        client
            .get(format!("http://127.0.0.1:{}/v1/shed", gateway.http_port))
            .send(),
    )
    .await
    .expect("shed request timed out")
    .expect("shed request");
    assert_eq!(
        shed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "second v1 request must hit the subset http1MaxPendingRequests=1 cap"
    );
    let shed_body = shed.text().await.unwrap_or_default();
    assert!(
        shed_body.contains("in-flight request limit reached"),
        "in-flight-cap response body should identify the shed honestly: {shed_body}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "shed request must not reach the backend"
    );

    let sibling = timeout(
        Duration::from_secs(10),
        client
            .get(format!("http://127.0.0.1:{}/v2/ok", gateway.http_port))
            .send(),
    )
    .await
    .expect("sibling request timed out")
    .expect("sibling subset request");
    assert_eq!(
        sibling.status(),
        StatusCode::OK,
        "sibling subset v2 must not share the v1 pending lane"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "sibling request must reach the backend immediately while v1 is held"
    );

    release.release();
    let held = hold.await.expect("held task join");
    assert_eq!(
        held.status(),
        StatusCode::OK,
        "held v1 request must complete"
    );

    let after = timeout(
        Duration::from_secs(10),
        client
            .get(format!("http://127.0.0.1:{}/v1/after", gateway.http_port))
            .send(),
    )
    .await
    .expect("post-release request timed out")
    .expect("post-release v1 request");
    assert_eq!(
        after.status(),
        StatusCode::OK,
        "pending permit must release after the held request completes"
    );

    let _ = shutdown_tx.send(true);
    gateway.shutdown().await;
    match timeout(Duration::from_secs(5), backend_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(err))) => panic!("holding backend failed: {err}"),
        Ok(Err(join_err)) => panic!("holding backend panicked: {join_err}"),
        Err(_) => panic!("holding backend did not exit after shutdown"),
    }
}

struct RunningGateway {
    http_port: u16,
    shutdown_tx: watch::Sender<bool>,
    join: JoinHandle<()>,
}

impl RunningGateway {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        match timeout(Duration::from_secs(5), self.join).await {
            Ok(Ok(())) => {}
            Ok(Err(join_err)) => panic!("subset gateway task panicked: {join_err}"),
            Err(_) => panic!("subset gateway shutdown timed out"),
        }
    }
}

#[derive(Clone, Copy)]
struct ExpectedSubsetPreparation {
    v1_h2_policy: H2UpgradePolicy,
    v2_h2_policy: H2UpgradePolicy,
    v1_port: u16,
    v2_port: u16,
    backend_scheme: &'static str,
    verify_server_cert: bool,
}

async fn start_subset_gateway(
    config: GatewayConfig,
    expected: ExpectedSubsetPreparation,
) -> Result<RunningGateway, Box<dyn std::error::Error + Send + Sync>> {
    let http = reserve_port().await?;
    let admin = reserve_port().await?;
    let http_port = http.port;
    let admin_port = admin.port;

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: "warn".to_string(),
        proxy_http_port: http_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(JWT_SECRET.to_string()),
        admin_jwt_issuer: JWT_ISSUER.to_string(),
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: NS.to_string(),
        ..EnvConfig::default()
    };
    let prepared = prepare_gateway_config_for_mesh(config, &mesh_runtime_config()).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("mesh preparation failed: {e}").into()
        },
    )?;
    assert_subset_preparation(&prepared, expected);

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });
    let opts = ServeOptions {
        proxy_http: Some(http.into_listener()),
        admin_http: Some(admin.into_listener()),
        admin_jwt_manager: Some(jwt_manager),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };
    let (shutdown_tx, _) = watch::channel(false);
    let handles = ferrum_edge::modes::file::serve(env_config, prepared, opts, shutdown_tx.clone())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("file::serve failed: {e}").into()
        })?;
    let join = tokio::spawn(async move {
        if let Err(err) = handles.join().await {
            panic!("in-process subset HTTP policy gateway listener failed: {err}");
        }
    });

    Ok(RunningGateway {
        http_port,
        shutdown_tx,
        join,
    })
}

fn assert_subset_preparation(config: &GatewayConfig, expected: ExpectedSubsetPreparation) {
    let upstream = config
        .upstreams
        .iter()
        .find(|upstream| upstream.id == UPSTREAM_ID)
        .expect("prepared subset upstream");
    assert_eq!(
        upstream.backend_tls_verify_server_cert, expected.verify_server_cert,
        "fixture TLS verification must be configured on the owning upstream"
    );

    for (subset, expected_policy, expected_port, expected_retries, expected_pending) in [
        ("v1", expected.v1_h2_policy, expected.v1_port, 1, 1),
        ("v2", expected.v2_h2_policy, expected.v2_port, 3, 50),
    ] {
        let proxy = config
            .proxies
            .iter()
            .find(|proxy| proxy.upstream_subset.as_deref() == Some(subset))
            .unwrap_or_else(|| panic!("prepared {subset} proxy"));
        let fallback = proxy
            .dispatch_port_override_fallback
            .as_ref()
            .unwrap_or_else(|| panic!("prepared {subset} subset fallback"));
        assert_eq!(
            fallback.h2_upgrade_policy,
            Some(expected_policy),
            "prepared {subset} must carry its exact selected-subset h2UpgradePolicy"
        );
        assert_eq!(
            fallback.max_retries,
            Some(expected_retries),
            "prepared {subset} must carry its exact selected-subset maxRetries"
        );
        assert_eq!(
            fallback.http1_max_pending_requests,
            Some(expected_pending),
            "prepared {subset} must carry its exact selected-subset http1MaxPendingRequests"
        );
        assert_eq!(
            proxy.backend_port, expected_port,
            "prepared {subset} proxy template must not retain a stale backend port"
        );
        assert_eq!(
            proxy.resolved_tls.verify_server_cert, expected.verify_server_cert,
            "prepared {subset} must inherit TLS verification from its upstream"
        );

        let target = upstream
            .targets
            .iter()
            .find(|target| target.tags.get("version").map(String::as_str) == Some(subset))
            .unwrap_or_else(|| panic!("prepared {subset} target"));
        assert_eq!(
            target.port, expected_port,
            "prepared {subset} target must dial the expected fixture port"
        );
        assert_eq!(
            target.dispatch_policy_port(),
            expected_port,
            "prepared {subset} target policy port must match its dial port"
        );

        let request_path = format!("/{subset}/probe");
        let strip_len = proxy.listen_path.as_deref().map(str::len).unwrap_or(0);
        let backend_url = build_backend_url_with_target(
            proxy,
            &request_path,
            "",
            &target.host,
            target.port,
            strip_len,
            target.path.as_deref(),
        );
        assert_eq!(
            backend_url,
            format!(
                "{}://127.0.0.1:{}/probe",
                expected.backend_scheme, expected_port
            ),
            "prepared {subset} backend URL must use the selected target dial port"
        );
    }
}

fn mesh_runtime_config() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "subset-http-node".to_string(),
        namespace: NS.to_string(),
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
        unix_socket_allowed_roots: Vec::new(),
        unix_socket_allowed_uids: Vec::new(),
        locality_lb_strict: false,
    }
}

fn subset_https_dual_backend_config(h1_port: u16, h2_port: u16) -> GatewayConfig {
    let mut config = subset_policy_config(
        h1_port,
        "https",
        json!({
            "connection_pool_http": {
                "h2_upgrade_policy": "UPGRADE",
                "max_retries": 5,
                "http1_max_pending_requests": 100
            }
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 1,
            "http1_max_pending_requests": 1
        }),
        json!({
            "h2_upgrade_policy": "UPGRADE",
            "max_retries": 3,
            "http1_max_pending_requests": 50
        }),
        None,
        false,
    );
    // Upstream-backed proxies inherit TLS posture from the upstream, not their
    // route template. These synthetic certificates are intentionally trusted by
    // this fixture only; production defaults remain fail-closed.
    for upstream in &mut config.upstreams {
        upstream.backend_tls_verify_server_cert = false;
        for target in &mut upstream.targets {
            if target.tags.get("version").map(String::as_str) == Some("v2") {
                target.port = h2_port;
            }
        }
    }
    // Keep the route templates aligned with the subset-selected dial targets so
    // preparation assertions cannot pass while a stale template port hides a
    // target-rebasing defect.
    config.proxies.retain_mut(|proxy| {
        match proxy.upstream_subset.as_deref() {
            Some("v1") => proxy.backend_port = h1_port,
            Some("v2") => proxy.backend_port = h2_port,
            _ => return false,
        }
        true
    });
    config
}

fn subset_http_retry_config(backend_port: u16) -> GatewayConfig {
    subset_policy_config(
        backend_port,
        "http",
        json!({
            "connection_pool_http": {
                "h2_upgrade_policy": "DO_NOT_UPGRADE",
                "max_retries": 5,
                "http1_max_pending_requests": 100
            }
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 1,
            "http1_max_pending_requests": 1
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 3,
            "http1_max_pending_requests": 50
        }),
        Some(json!({
            "max_retries": 5,
            "retryable_status_codes": [503],
            "retryable_methods": ["GET"],
            "retry_on_connect_failure": false
        })),
        true,
    )
}

fn subset_http_pending_config(backend_port: u16) -> GatewayConfig {
    subset_policy_config(
        backend_port,
        "http",
        json!({
            "connection_pool_http": {
                "h2_upgrade_policy": "DO_NOT_UPGRADE",
                "max_retries": 5,
                "http1_max_pending_requests": 100
            }
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 1,
            "http1_max_pending_requests": 1
        }),
        json!({
            "h2_upgrade_policy": "DO_NOT_UPGRADE",
            "max_retries": 3,
            "http1_max_pending_requests": 50
        }),
        None,
        true,
    )
}

fn subset_policy_config(
    backend_port: u16,
    backend_scheme: &str,
    top_level: serde_json::Value,
    v1_http: serde_json::Value,
    v2_http: serde_json::Value,
    retry: Option<serde_json::Value>,
    force_h1_pool: bool,
) -> GatewayConfig {
    let mut proxies = Vec::new();
    for (id, path, subset) in [
        ("subset-v1", "/v1", Some("v1")),
        ("subset-v2", "/v2", Some("v2")),
        ("subset-unmatched", "/unmatched", None),
    ] {
        let mut proxy = json!({
            "id": id,
            "namespace": NS,
            "listen_path": path,
            "backend_scheme": backend_scheme,
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "upstream_id": UPSTREAM_ID,
            "pool_enable_http2": !force_h1_pool
        });
        if let Some(subset) = subset {
            proxy["upstream_subset"] = json!(subset);
        }
        if force_h1_pool {
            proxy["pool_enable_http2"] = json!(false);
        }
        if let Some(retry) = retry.clone() {
            proxy["retry"] = retry;
        }
        proxies.push(proxy);
    }

    serde_json::from_value(json!({
        "version": "1",
        "proxies": proxies,
        "upstreams": [{
            "id": UPSTREAM_ID,
            "namespace": NS,
            "name": "subset HTTP policy upstream",
            "algorithm": "round_robin",
            "targets": [
                {
                    "host": "127.0.0.1",
                    "port": backend_port,
                    "weight": 1,
                    "tags": { "version": "v1" }
                },
                {
                    "host": "127.0.0.1",
                    "port": backend_port,
                    "weight": 1,
                    "tags": { "version": "v2" }
                }
            ],
            "subsets": [
                {
                    "name": "v1",
                    "labels": { "version": "v1" }
                },
                {
                    "name": "v2",
                    "labels": { "version": "v2" }
                }
            ]
        }],
        "consumers": [],
        "plugin_configs": [],
        "mesh": {
            "destination_rules": [{
                "name": "subset-http-dr",
                "namespace": NS,
                "host": UPSTREAM_ID,
                "traffic_policy": top_level,
                "subsets": [
                    {
                        "name": "v1",
                        "labels": { "version": "v1" },
                        "traffic_policy": {
                            "connection_pool_http": v1_http
                        }
                    },
                    {
                        "name": "v2",
                        "labels": { "version": "v2" },
                        "traffic_policy": {
                            "connection_pool_http": v2_http
                        }
                    }
                ]
            }]
        }
    }))
    .expect("subset policy config is valid")
}

struct ReleaseGate {
    released: AtomicBool,
    notify: Notify,
}

impl ReleaseGate {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

type BackendTaskResult = Result<(), String>;

async fn spawn_holding_backend() -> (
    u16,
    Arc<AtomicUsize>,
    oneshot::Receiver<()>,
    Arc<ReleaseGate>,
    watch::Sender<bool>,
    JoinHandle<BackendTaskResult>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind holding backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let (first_hit_tx, first_hit_rx) = oneshot::channel();
    let release = Arc::new(ReleaseGate::new());
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let task_hits = Arc::clone(&hits);
    let task_release = Arc::clone(&release);
    let task = tokio::spawn(async move {
        let mut children = JoinSet::new();
        let mut hold_assigned = false;
        let mut first_hit_tx = Some(first_hit_tx);
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted.map_err(|e| format!("holding accept failed: {e}"))?;
                    let hits = Arc::clone(&task_hits);
                    let first_hit_tx = if !hold_assigned {
                        hold_assigned = true;
                        first_hit_tx.take()
                    } else {
                        None
                    };
                    let hold = if first_hit_tx.is_some() {
                        Some(Arc::clone(&task_release))
                    } else {
                        None
                    };
                    children.spawn(async move {
                        serve_held_http(stream, &hits, hold.as_ref(), first_hit_tx)
                            .await
                            .map_err(|e| format!("holding connection failed: {e}"))
                    });
                }
                Some(joined) = children.join_next() => {
                    match joined {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => return Err(err),
                        Err(join_err) => {
                            return Err(format!("holding connection task panicked: {join_err}"));
                        }
                    }
                }
            }
        }
        while let Some(joined) = children.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(join_err) => {
                    return Err(format!("holding connection task panicked: {join_err}"));
                }
            }
        }
        Ok(())
    });
    (port, hits, first_hit_rx, release, shutdown_tx, task)
}

async fn spawn_status_script_backend(
    statuses: &[StatusCode],
) -> (
    u16,
    Arc<AtomicUsize>,
    watch::Sender<bool>,
    JoinHandle<BackendTaskResult>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind status backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let script: Vec<u16> = statuses.iter().map(|s| s.as_u16()).collect();
    let task_hits = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        // Sequential accept+serve is enough for the retry script and keeps
        // every child error on the parent task result.
        let mut idx = 0usize;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted.map_err(|e| format!("status accept failed: {e}"))?;
                    let status = script.get(idx).copied().unwrap_or(200);
                    idx = idx.saturating_add(1);
                    serve_status_http(stream, &task_hits, status)
                        .await
                        .map_err(|e| format!("status connection failed: {e}"))?;
                }
            }
        }
        Ok(())
    });
    (port, hits, shutdown_tx, task)
}

async fn serve_held_http(
    mut stream: TcpStream,
    hits: &AtomicUsize,
    release: Option<&Arc<ReleaseGate>>,
    first_hit_tx: Option<oneshot::Sender<()>>,
) -> std::io::Result<()> {
    read_headers(&mut stream).await?;
    hits.fetch_add(1, Ordering::SeqCst);
    if let Some(tx) = first_hit_tx {
        let _ = tx.send(());
    }
    if let Some(release) = release {
        release.wait().await;
    }
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn serve_status_http(
    mut stream: TcpStream,
    hits: &AtomicUsize,
    status: u16,
) -> std::io::Result<()> {
    read_headers(&mut stream).await?;
    hits.fetch_add(1, Ordering::SeqCst);
    let body = if status == 200 { "ok" } else { "retry" };
    let response = format!(
        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn read_headers(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0; 8192];
    let mut read = 0;
    loop {
        let n = timeout(Duration::from_secs(5), stream.read(&mut buf[read..]))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "header read timed out")
            })??;
        if n == 0 {
            return Ok(());
        }
        read += n;
        if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(());
        }
        if read == buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
    }
}
