//! `request_deduplication` dispatch provenance through the H3 → HTTP/1.1
//! cross-protocol bridge (`src/http3/cross_protocol.rs`).
//!
//! A proven pre-wire backend failure must release the in-flight lease once the
//! gateway terminal is committed, exactly as on HTTP/1.1 and HTTP/2
//! (`scaffolding::dedup_dispatch`): an immediate retry under the same
//! idempotency key executes instead of being refused with `409` until
//! `inflight_ttl_seconds` expires. A failure that may have executed keeps the
//! lease.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{ServeHandles, ServeOptions};
use http::{Method, StatusCode};
use serde_json::json;

use crate::scaffolding::backends::{Http1Request, HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::{reserve_colocated_tcp_udp, reserve_port, reserve_refused_tcp_port};

const WAIT: Duration = Duration::from_secs(15);

struct H3DedupGateway {
    https_port: u16,
    shutdown: ferrum_edge::overload::ShutdownSender,
    handles: Option<ServeHandles>,
}

impl H3DedupGateway {
    async fn start(config: GatewayConfig) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (https, udp) = reserve_colocated_tcp_udp()
            .await
            .expect("HTTPS/H3 reservation");
        let https_port = https.port;
        let env = EnvConfig {
            mode: OperatingMode::File,
            proxy_http_port: 0,
            proxy_https_port: https_port,
            admin_http_port: 0,
            admin_https_port: 0,
            frontend_tls_cert_path: Some("tests/certs/server.crt".to_string()),
            frontend_tls_key_path: Some("tests/certs/server.key".to_string()),
            enable_http3: true,
            pool_warmup_enabled: false,
            shutdown_drain_seconds: 0,
            max_connections: 0,
            ..EnvConfig::default()
        };
        let options = ServeOptions {
            proxy_https: Some(https.into_listener()),
            skip_initial_capability_refresh: true,
            ..ServeOptions::default()
        };
        drop(udp);
        let (shutdown, _) = ferrum_edge::overload::ShutdownSender::channel(Duration::ZERO);
        let handles = ferrum_edge::modes::file::serve(env, config, options, shutdown.clone())
            .await
            .expect("in-process H3 dedup gateway");
        Self {
            https_port,
            shutdown,
            handles: Some(handles),
        }
    }

    async fn shutdown(mut self) {
        self.shutdown.shutdown();
        tokio::time::timeout(WAIT, self.handles.take().expect("handles").join())
            .await
            .expect("gateway shutdown deadline")
            .expect("gateway tasks");
    }
}

impl Drop for H3DedupGateway {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        if let Some(handles) = self.handles.take() {
            tokio::spawn(async move {
                let _ = handles.join().await;
            });
        }
    }
}

fn config(backend_port: u16, read_timeout_ms: u64) -> GatewayConfig {
    serde_json::from_value(json!({
        "version": "1",
        "proxies": [{
            "id": "h3-dedup", "listen_path": "/dedup",
            "backend_scheme": "http", "backend_host": "127.0.0.1",
            "backend_port": backend_port, "strip_listen_path": true,
            // Darwin drops a SYN to a bound-but-unlistened port instead of
            // answering RST, so keep the pre-wire connect failure prompt there.
            "backend_connect_timeout_ms": 500, "backend_read_timeout_ms": read_timeout_ms,
            "backend_write_timeout_ms": 5000,
            "plugins": [{"plugin_config_id": "h3-dedup-plugin"}]
        }],
        "plugin_configs": [{
            "id": "h3-dedup-plugin", "plugin_name": "request_deduplication",
            "scope": "proxy", "proxy_id": "h3-dedup", "enabled": true,
            "config": {
                "ttl_seconds": 60,
                "inflight_ttl_seconds": 30,
                "scope_by_consumer": false,
                "applicable_methods": ["POST"]
            }
        }],
        "consumers": [], "upstreams": []
    }))
    .expect("H3 dedup config")
}

async fn post(gateway: &H3DedupGateway, key: &str) -> Http3Response {
    let client = Http3Client::insecure().expect("H3 client");
    let options = GetOptions::default()
        .method(Method::POST)
        .header("idempotency-key", key)
        .header("content-type", "application/octet-stream")
        .body(bytes::Bytes::from_static(b"operation"));
    let response = client
        .get_with_options(
            &format!("https://localhost:{}/dedup/operation", gateway.https_port),
            options,
        )
        .await
        .expect("H3 gateway response");
    client.close();
    response
}

fn is_operation(request: &Http1Request) -> bool {
    request.method == "POST" && request.path == "/operation"
}

/// H3 frontend, HTTP/1.1 backend: a refused (pre-wire) first dispatch must
/// not leave the idempotency key leased.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_bridge_pre_wire_failure_releases_dedup_inflight_lease() {
    let refused = reserve_refused_tcp_port().expect("reserve refused backend");
    let gateway = H3DedupGateway::start(config(refused.port, 5000)).await;

    let failed = post(&gateway, "h3-prewire").await;
    assert!(
        matches!(
            failed.status,
            StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
        ),
        "pre-wire dispatch failure must be a gateway terminal, got {failed:?}"
    );
    assert!(failed.headers.get("x-idempotent-replayed").is_none());

    let backend = ScriptedHttp1Backend::builder(refused.into_listener().expect("activate backend"))
        .step(HttpStep::ExpectRequest(RequestMatcher::custom(
            is_operation,
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"done".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("start recovered backend");

    // The retry is immediate: well inside `inflight_ttl_seconds`. A lease the
    // pre-wire failure left held answers it with `409`.
    let retry = post(&gateway, "h3-prewire").await;
    assert_eq!(
        retry.status,
        StatusCode::OK,
        "a proven pre-wire failure must release the in-flight lease: {retry:?} ({})",
        retry.body_text()
    );
    assert!(retry.headers.get("x-idempotent-replayed").is_none());
    assert_eq!(retry.body_text(), "done");

    let replay = post(&gateway, "h3-prewire").await;
    assert_eq!(replay.status, StatusCode::OK);
    assert_eq!(replay.headers["x-idempotent-replayed"], "true");
    assert_eq!(replay.body_text(), "done");

    backend.assert_no_matcher_mismatches().await;
    let requests = backend.received_requests().await;
    assert_eq!(
        requests
            .iter()
            .filter(|request| is_operation(request))
            .count(),
        1,
        "exactly one application write; observed requests: {requests:?}"
    );
    gateway.shutdown().await;
    drop(backend);
}

/// H3 frontend, HTTP/1.1 backend: the backend consumes the operation and then
/// closes before any status byte. The bridge answers a classified `502` through
/// its gateway error terminal, whose committed observers now run; the attempt
/// reached the wire, so they must keep the lease and refuse the retry without
/// a second backend write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_bridge_post_wire_close_retains_dedup_inflight_lease() {
    let reserved = reserve_port().await.expect("reserve closing backend");
    let port = reserved.port;
    let executed = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&executed);
    let backend = ScriptedHttp1Backend::builder(reserved.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::custom(
            move |request| {
                let operation = is_operation(request);
                if operation {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                operation
            },
        )))
        .step(HttpStep::CloseBeforeStatus)
        .spawn()
        .expect("start closing backend");
    let gateway = H3DedupGateway::start(config(port, 5000)).await;

    let failed = post(&gateway, "h3-postwire-close").await;
    assert_eq!(
        failed.status,
        StatusCode::BAD_GATEWAY,
        "a backend that closed before its head must be a gateway 502: {failed:?}"
    );
    assert!(failed.headers.get("x-idempotent-replayed").is_none());
    assert_eq!(executed.load(Ordering::SeqCst), 1, "backend executed");

    let retry = post(&gateway, "h3-postwire-close").await;
    assert_eq!(
        retry.status,
        StatusCode::CONFLICT,
        "a failure that may have executed must keep the in-flight lease: {retry:?}"
    );
    assert!(retry.headers.get("x-idempotent-replayed").is_none());
    assert_eq!(
        executed.load(Ordering::SeqCst),
        1,
        "no second application write"
    );

    gateway.shutdown().await;
    drop(backend);
}

/// H3 frontend, HTTP/1.1 backend: the backend executes the operation and then
/// withholds its response head past `backend_read_timeout_ms`. The gateway's
/// `504` is not proof the operation failed, so the lease stays held and the
/// retry is refused without a second backend write. This backend-timeout
/// terminal runs no committed observers, so the lease is kept by omission; the
/// close-before-head case above is the one that guards the observer path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_bridge_post_wire_timeout_retains_dedup_inflight_lease() {
    let reserved = reserve_port().await.expect("reserve slow backend");
    let port = reserved.port;
    let executed = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&executed);
    let backend = ScriptedHttp1Backend::builder(reserved.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::custom(
            move |request| {
                let operation = is_operation(request);
                if operation {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                operation
            },
        )))
        .step(HttpStep::Sleep(Duration::from_secs(3)))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"done".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("start slow backend");
    let gateway = H3DedupGateway::start(config(port, 500)).await;

    let timed_out = post(&gateway, "h3-postwire").await;
    assert_eq!(
        timed_out.status,
        StatusCode::GATEWAY_TIMEOUT,
        "a withheld response head must be a gateway timeout: {timed_out:?}"
    );
    assert!(timed_out.headers.get("x-idempotent-replayed").is_none());
    assert_eq!(executed.load(Ordering::SeqCst), 1, "backend executed");

    let retry = post(&gateway, "h3-postwire").await;
    assert_eq!(
        retry.status,
        StatusCode::CONFLICT,
        "a failure that may have executed must keep the in-flight lease: {retry:?}"
    );
    assert!(retry.headers.get("x-idempotent-replayed").is_none());
    assert_eq!(
        executed.load(Ordering::SeqCst),
        1,
        "no second application write"
    );

    gateway.shutdown().await;
    drop(backend);
}
