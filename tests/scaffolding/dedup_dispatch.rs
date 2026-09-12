//! Shared local and two-process Redis dispatch-provenance acceptance cases.

use super::backends::{Http1Request, HttpStep, RequestMatcher, ScriptedHttp1Backend};
use super::harness::GatewayHarness;
use super::ports::{reserve_port, reserve_refused_tcp_port};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn config(port: u16, read_timeout_ms: u64, redis: Option<&Value>) -> String {
    let mut plugin = json!({
        "ttl_seconds": 60,
        "inflight_ttl_seconds": 30,
        "scope_by_consumer": false,
        "applicable_methods": ["POST"]
    });
    if let Some(redis) = redis {
        plugin
            .as_object_mut()
            .unwrap()
            .extend(redis.as_object().unwrap().clone());
    }
    super::to_file_mode_yaml(&json!({
        "version": "1",
        "proxies": [{
            "id": "dedup-dispatch", "listen_path": "/dedup",
            "backend_scheme": "http", "backend_host": "127.0.0.1", "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000, "backend_read_timeout_ms": read_timeout_ms,
            "backend_write_timeout_ms": 5000,
            "plugins": [{"plugin_config_id": "dedup-dispatch-plugin"}]
        }],
        "plugin_configs": [{
            "id": "dedup-dispatch-plugin", "plugin_name": "request_deduplication",
            "scope": "proxy", "proxy_id": "dedup-dispatch", "enabled": true, "config": plugin
        }],
        "consumers": [], "upstreams": []
    }))
}

async fn gateways(yaml: &str, distributed: bool) -> (GatewayHarness, Option<GatewayHarness>) {
    let spawn = || async {
        let builder = GatewayHarness::builder()
            .file_config(yaml)
            .pool_warmup_enabled(false);
        let builder = if distributed {
            builder.mode_binary()
        } else {
            builder.mode_in_process()
        };
        builder.spawn().await.expect("start dedup gateway")
    };
    let first = spawn().await;
    let peer = if distributed {
        Some(spawn().await)
    } else {
        None
    };
    (first, peer)
}

async fn post(gateway: &GatewayHarness, key: &str) -> reqwest::Response {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
        .post(gateway.proxy_url("/dedup/operation"))
        // Both processes must expose the same logical authority/fingerprint.
        .header("host", "dedup.test")
        .header("idempotency-key", key)
        .header("content-type", "application/octet-stream")
        .body("operation")
        .send()
        .await
        .expect("gateway response")
}

fn assert_not_replayed(response: &reqwest::Response) {
    assert!(response.headers().get("x-idempotent-replayed").is_none());
}

fn is_operation(request: &Http1Request) -> bool {
    request.method == "POST" && request.path == "/operation"
}

fn is_capability_probe(request: &Http1Request) -> bool {
    // Binary gateways perform an initial h2c capability probe even when pool
    // warmup is disabled. Its connection preface is not an application write.
    request.method == "PRI" && request.path == "*" && request.version == "HTTP/2.0"
}

fn operation_or_capability_probe() -> RequestMatcher {
    RequestMatcher::custom(|request| is_operation(request) || is_capability_probe(request))
}

async fn assert_one_operation(backend: &ScriptedHttp1Backend) {
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
}

pub async fn assert_dispatch_provenance(redis: Option<Value>) {
    let distributed = redis.is_some();

    // Keep a socket bound without listening, then promote that exact socket:
    // no bind/drop/rebind race and the first operation provably cannot execute.
    let refused = reserve_refused_tcp_port().expect("reserve refused backend");
    let (first, peer) = gateways(&config(refused.port, 5000, redis.as_ref()), distributed).await;
    let failed = post(&first, "prewire").await;
    assert_eq!(failed.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_not_replayed(&failed);
    let _ = failed.bytes().await.expect("consume gateway failure");
    let backend = ScriptedHttp1Backend::builder(refused.into_listener().expect("activate backend"))
        .step(HttpStep::ExpectRequest(operation_or_capability_probe()))
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
    let retry = post(peer.as_ref().unwrap_or(&first), "prewire").await;
    assert_eq!(retry.status(), reqwest::StatusCode::OK);
    assert_not_replayed(&retry);
    assert_eq!(retry.text().await.unwrap(), "done");
    let replay = post(&first, "prewire").await;
    assert_eq!(replay.status(), reqwest::StatusCode::OK);
    assert_eq!(replay.headers()["x-idempotent-replayed"], "true");
    assert_eq!(replay.text().await.unwrap(), "done");
    assert_one_operation(&backend).await;
    drop((first, peer, backend));

    // The backend commits its operation before withholding response headers.
    // A gateway timeout cannot truthfully publish that operation as failed.
    let reserved = reserve_port().await.expect("reserve slow backend");
    let port = reserved.port;
    let completed = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&completed);
    let backend = ScriptedHttp1Backend::builder(reserved.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::custom(
            move |request| {
                if is_operation(request) {
                    observed.fetch_add(1, Ordering::SeqCst);
                    true
                } else {
                    is_capability_probe(request)
                }
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
    let (first, peer) = gateways(&config(port, 500, redis.as_ref()), distributed).await;
    let timed_out = post(&first, "postwire").await;
    assert_eq!(timed_out.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);
    assert_not_replayed(&timed_out);
    let _ = timed_out.bytes().await.unwrap();
    assert_eq!(
        completed.load(Ordering::SeqCst),
        1,
        "backend operation completed"
    );
    for gateway in [&first, peer.as_ref().unwrap_or(&first)] {
        let retry = post(gateway, "postwire").await;
        assert_eq!(retry.status(), reqwest::StatusCode::CONFLICT);
        assert_not_replayed(&retry);
        let _ = retry.bytes().await.unwrap();
    }
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    assert_one_operation(&backend).await;
    drop((first, peer, backend));

    // Equal HTTP statuses have different provenance. Backend 500/502/504 must
    // still be retained; a status allowlist is not a fix for dispatch failures.
    for status in [500, 502, 504] {
        let reserved = reserve_port().await.expect("reserve status backend");
        let port = reserved.port;
        let backend = ScriptedHttp1Backend::builder(reserved.into_listener())
            .step(HttpStep::ExpectRequest(operation_or_capability_probe()))
            .step(HttpStep::RespondStatus {
                status,
                reason: "Backend Result".into(),
            })
            .step(HttpStep::RespondHeader {
                name: "Content-Length".into(),
                value: "4".into(),
            })
            .step(HttpStep::RespondBodyChunk(b"real".to_vec()))
            .step(HttpStep::RespondBodyEnd)
            .spawn()
            .expect("start status backend");
        let (first, peer) = gateways(&config(port, 5000, redis.as_ref()), distributed).await;
        let key = format!("backend-{status}");
        let original = post(&first, &key).await;
        assert_eq!(original.status().as_u16(), status);
        assert_not_replayed(&original);
        assert_eq!(original.text().await.unwrap(), "real");
        let replay = post(peer.as_ref().unwrap_or(&first), &key).await;
        assert_eq!(replay.status().as_u16(), status);
        assert_eq!(replay.headers()["x-idempotent-replayed"], "true");
        assert_eq!(replay.text().await.unwrap(), "real");
        assert_one_operation(&backend).await;
    }
}
