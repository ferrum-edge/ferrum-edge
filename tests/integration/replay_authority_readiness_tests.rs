//! A shared single-use replay authority outage reaches admin readiness
//! (issues #3834 / #3837).
//!
//! `jwks_auth`'s DPoP proofs and `hmac_auth`'s `ferrum-hmac-v2` nonces claim
//! against one shared authority. A `shared` policy has **no local fallback** by
//! design, so while its backend is unavailable every protected request on it
//! fails closed. That is a lost dependency rather than a per-request error: an
//! orchestrator must stop steering authenticated traffic at a replica that can
//! only refuse it.
//!
//! These cases drive the real admin `/health`, `/status`, and `/live` surfaces
//! over HTTP — not the aggregate helper alone — and cover:
//!
//! - a configured shared authority that has never proven its backend failing
//!   readiness with `unavailable` (unknown/unproven is fail-closed),
//! - a topology-screened recovery restoring readiness with no restart, no
//!   config reload, no protected traffic, and no manual state injection,
//! - a retired plugin generation dropping out of the aggregate entirely,
//! - the authenticated tier carrying the bounded aggregate while the
//!   unauthenticated tier keeps the repository's coarse `status` + `ready`
//!   contract, and
//! - `/live` staying healthy throughout.

use crate::scaffolding::port_registry::TestSocket;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use ferrum_edge::plugins::utils::replay_authority::{ReplayAuthority, shared_health_snapshot};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use serde_json::Value;

const METRICS_TOKEN: &str = "replay-authority-readiness-metrics-token";
const RETENTION: Duration = Duration::from_secs(601);

/// The shared-authority health counters are process-global, so these cases
/// serialize against one another. Nothing else in this test binary registers a
/// shared replay authority.
static REGISTRY_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: "replay-authority-readiness-test-secret-0000000".to_string(),
        issuer: "ferrum-edge-replay-authority-readiness-test".to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_state() -> AdminState {
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
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
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
        runtime_config_apply: None,
    }
}

async fn start_admin() -> (String, tokio::sync::watch::Sender<bool>) {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind admin");
    let addr = listener.local_addr().expect("admin addr");
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            admin_state(),
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

/// A shared authority pointed at a closed loopback port, exactly as a `shared`
/// `hmac_auth` / `jwks_auth` policy builds one.
fn shared_client(prefix: &str) -> Arc<RedisRateLimitClient> {
    shared_client_for_url(
        prefix,
        "redis://readiness-user:readiness-password@127.0.0.1:1/0",
        3600,
    )
}

fn shared_client_for_url(
    prefix: &str,
    redis_url: &str,
    health_check_interval_seconds: u64,
) -> Arc<RedisRateLimitClient> {
    let config = RedisConfig::from_plugin_config(
        &serde_json::json!({
            "sync_mode": "redis",
            "redis_url": redis_url,
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": health_check_interval_seconds,
        }),
        prefix,
    )
    .expect("redis config parses")
    .expect("sync_mode redis yields a config");
    Arc::new(
        RedisRateLimitClient::for_replay_authority(config, None, false, None)
            .expect("construction without a CA path must succeed"),
    )
}

const INFO_CMD: &[u8] = b"$4\r\nINFO\r\n";
const INFO_MEMORY_ARG: &[u8] = b"$6\r\nMEMORY\r\n";
const CLUSTER_DISABLED_INFO: &str = "# Cluster\r\ncluster_enabled:0\r\n";
const SAFE_MEMORY_INFO: &str = "# Memory\r\nmaxmemory:0\r\nmaxmemory_policy:noeviction\r\n";

fn resp_command_count(chunk: &[u8]) -> usize {
    chunk.iter().filter(|&&byte| byte == b'*').count().max(1)
}

fn resp_contains(chunk: &[u8], command: &[u8]) -> bool {
    chunk.windows(command.len()).any(|window| window == command)
}

/// Gated RESP peer: when closed, accepted sockets are dropped so the probe
/// fails fast; when open, handshake/PING succeed, `INFO CLUSTER` reports a
/// usable non-Cluster topology, and `INFO MEMORY` proves a no-eviction
/// posture. Recovery is proven by those screens, not by PING alone and not
/// by a protected `SET`.
async fn spawn_gated_replay_redis(
    initially_open: bool,
) -> (u16, Arc<AtomicBool>, tokio::sync::oneshot::Sender<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind fake redis");
    let port = listener.local_addr().expect("local addr").port();
    let open = Arc::new(AtomicBool::new(initially_open));
    let open_for_server = Arc::clone(&open);
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    if !open_for_server.load(Ordering::Acquire) {
                        drop(stream);
                        continue;
                    }
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            let read = match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(read) => read,
                            };
                            let chunk = &buf[..read];
                            let reply: Vec<u8> = if resp_contains(chunk, INFO_CMD) {
                                let text = if resp_contains(chunk, INFO_MEMORY_ARG) {
                                    SAFE_MEMORY_INFO
                                } else {
                                    CLUSTER_DISABLED_INFO
                                };
                                format!("${}\r\n{text}\r\n", text.len()).into_bytes()
                            } else {
                                b"+OK\r\n".repeat(resp_command_count(chunk))
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });

    (port, open, shutdown_tx)
}

async fn wait_for_health(base: &str, want_ready: bool, what: &str) -> (u16, Value) {
    let mut last = (0u16, Value::Null);
    for _ in 0..400 {
        last = get(base, "/health", Some(METRICS_TOKEN)).await;
        if last.0 == (if want_ready { 200 } else { 503 }) && last.1["ready"] == want_ready {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "timed out waiting until {what}: status={} body={}",
        last.0, last.1
    );
}

/// The whole lifecycle on the real admin surface: unproven/dead → recovered →
/// retired. Recovery is a screened probe, not protected traffic or test hooks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shared_replay_authority_outage_fails_readiness_and_recovery_restores_it() {
    let _serialized = REGISTRY_LOCK.lock().await;
    let (base, shutdown) = start_admin().await;

    // No shared authority configured at all: readiness is unaffected and the
    // authenticated body carries no aggregate.
    let (code, body) = get(&base, "/health", Some(METRICS_TOKEN)).await;
    assert_eq!(code, 200);
    assert_eq!(body["ready"], true);
    assert!(
        body.get("replay_authority").is_none(),
        "the aggregate is published only when a shared authority exists: {body}"
    );

    let dead = shared_client("ferrum:replay_readiness:lifecycle-dead");
    let dead_authority = ReplayAuthority::shared(Arc::clone(&dead), RETENTION);
    dead_authority.activate();
    assert_eq!(dead_authority.mode(), "shared");
    assert!(
        !dead.is_available(),
        "a replay client must start unproven, not reachable-so-far"
    );

    // Registered against a dead backend: fail closed on the real admin surface
    // without waiting for a protected request to touch Redis.
    let (code, body) = get(&base, "/health", Some(METRICS_TOKEN)).await;
    assert_eq!(code, 503, "an unproven shared authority fails readiness");
    assert_eq!(body["ready"], false);
    assert_eq!(
        body["status"], "unavailable",
        "a `shared` policy has no fallback, so this is a lost dependency"
    );
    assert_eq!(body["replay_authority"]["shared_authorities"], 1);
    assert_eq!(
        body["replay_authority"]["shared_authorities_unavailable"],
        1
    );

    // `/status` is the same handler and must agree.
    let (code, status_body) = get(&base, "/status", Some(METRICS_TOKEN)).await;
    assert_eq!(code, 503);
    assert_eq!(status_body["ready"], false);
    assert_eq!(status_body["status"], "unavailable");

    // Liveness is never affected: the process is healthy, a dependency is not.
    let (code, live) = get(&base, "/live", None).await;
    assert_eq!(code, 200);
    assert_eq!(live, serde_json::json!({"status": "ok"}));

    drop(dead_authority);
    drop(dead);
    let (code, body) = get(&base, "/health", Some(METRICS_TOKEN)).await;
    assert_eq!(
        code, 200,
        "a retired dead generation must not keep readiness down: {body}"
    );

    // Recovery without protected traffic: start closed, then open a screened
    // RESP peer. The background probe — not admit() and not publish_reachable
    // — must restore `/health`.
    let (port, open, redis_shutdown) = spawn_gated_replay_redis(false).await;
    let redis_url = format!("redis://readiness-user:readiness-password@127.0.0.1:{port}/0");
    let recovering =
        shared_client_for_url("ferrum:replay_readiness:lifecycle-recover", &redis_url, 1);
    let recovering_authority = ReplayAuthority::shared(Arc::clone(&recovering), RETENTION);
    recovering_authority.activate();
    let (code, body) = wait_for_health(&base, false, "gated backend starts unproven").await;
    assert_eq!(code, 503);
    assert_eq!(
        body["replay_authority"]["shared_authorities_unavailable"],
        1
    );

    open.store(true, Ordering::Release);
    let (code, body) = wait_for_health(
        &base,
        true,
        "screened probe restores readiness without protected traffic",
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(body["ready"], true);
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["replay_authority"]["shared_authorities_unavailable"],
        0
    );
    assert!(
        recovering.is_available(),
        "readiness recovery must match the client availability word"
    );

    drop(recovering_authority);
    drop(recovering);
    let (code, body) = get(&base, "/health", Some(METRICS_TOKEN)).await;
    assert_eq!(
        code, 200,
        "a retired generation must not keep readiness down: {body}"
    );
    assert_eq!(body["ready"], true);
    assert!(
        body.get("replay_authority").is_none(),
        "a retired generation must not remain counted: {body}"
    );
    assert_eq!(shared_health_snapshot().shared_authorities, 0);

    let _ = redis_shutdown.send(());
    let _ = shutdown.send(true);
}

/// The unauthenticated probe keeps the repository's coarse observability
/// contract: exactly `status` + `ready`, and none of the aggregate, the
/// endpoint, or its credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_unauthenticated_probe_sees_readiness_but_not_the_aggregate() {
    let _serialized = REGISTRY_LOCK.lock().await;
    let (base, shutdown) = start_admin().await;

    let client = shared_client("ferrum:replay_readiness:coarse");
    let authority = ReplayAuthority::shared(Arc::clone(&client), RETENTION);
    authority.activate();

    let (code, anonymous) = get(&base, "/health", None).await;
    assert_eq!(code, 503);
    assert_eq!(anonymous["status"], "unavailable");
    assert_eq!(anonymous["ready"], false);
    let object = anonymous.as_object().expect("object body");
    assert_eq!(
        object.len(),
        2,
        "the unauthenticated body must stay exactly status+ready: {anonymous}"
    );
    let rendered = anonymous.to_string();
    for forbidden in [
        "replay_authority",
        "shared_authorities",
        "redis",
        "readiness-user",
        "readiness-password",
        "127.0.0.1:1",
        "ferrum:replay_readiness",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "unauthenticated health leaked {forbidden:?}: {rendered}"
        );
    }

    // The authenticated tier gets the aggregate — and nothing beyond the two
    // fixed-cardinality counters.
    let (code, detailed) = get(&base, "/health", Some(METRICS_TOKEN)).await;
    assert_eq!(code, 503);
    let aggregate = detailed["replay_authority"]
        .as_object()
        .expect("the aggregate is published to the authenticated tier");
    assert_eq!(aggregate.len(), 2, "fixed cardinality: {detailed}");
    assert_eq!(aggregate["shared_authorities"], 1);
    assert_eq!(aggregate["shared_authorities_unavailable"], 1);
    let rendered = detailed.to_string();
    for forbidden in [
        "readiness-user",
        "readiness-password",
        "127.0.0.1:1",
        "ferrum:replay_readiness",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "authenticated health leaked {forbidden:?}: {rendered}"
        );
    }

    drop(authority);
    drop(client);
    let _ = shutdown.send(true);
}
