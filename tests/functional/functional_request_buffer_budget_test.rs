//! Issue #4153 — transport proof that a buffered client request body is never
//! collected without a finite ceiling.
//!
//! The unit suite covers the folding rule and the aggregate admission. What
//! only a real gateway can prove is the operator-visible consequence: with
//! `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0` ("unlimited") and a plugin that
//! declares `requires_request_body_buffering`, an upload above the fail-closed
//! fallback is refused `413` rather than collected — while a route with no
//! buffering plugin, which the gateway STREAMS, is untouched by the same
//! ceiling and still forwards the identical payload.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{TestGateway, TestGatewayBuilder};

use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// The fail-closed fallback this gateway is configured with. One 64 KiB
/// reservation block is the smallest value the runtime clamp accepts, which
/// keeps the oversized payload below small enough for a functional test.
const FALLBACK_BYTES: usize = 65_536;

/// Comfortably above `FALLBACK_BYTES` once the JSON envelope is added.
const OVERSIZED_PAYLOAD_BYTES: usize = 200_000;

fn json_body(payload_bytes: usize) -> String {
    format!(r#"{{"name":"{}"}}"#, "a".repeat(payload_bytes))
}

#[ignore]
#[tokio::test]
async fn buffered_request_over_the_fail_closed_fallback_is_rejected_when_the_limit_is_zero() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = budget_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start request-buffer-budget gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http1 client");

    // `/buffered` carries `body_validator`, so the gateway must collect the
    // whole upload before the request can proceed. Before this fix a `0` limit
    // took a raw `collect()` here with no bound at all.
    // The gateway refuses on the declared length without draining the upload
    // (draining an over-ceiling body would be the DoS this fix closes), so the
    // client may observe the 413 or may instead see its own write fail once the
    // gateway closes the connection. Both are valid rejections; the
    // backend-not-hit assertion below is the authoritative check.
    match client
        .post(gateway.proxy_url("/buffered"))
        .header("content-type", "application/json")
        .body(json_body(OVERSIZED_PAYLOAD_BYTES))
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            assert_eq!(
                status,
                reqwest::StatusCode::PAYLOAD_TOO_LARGE,
                "an unlimited limit must still fail closed on the buffered path; \
                 got {status} {body}"
            );
            assert!(
                body.contains("Request body exceeds maximum size"),
                "unexpected body: {body}"
            );
        }
        Err(error) => {
            assert!(
                !error.is_timeout(),
                "the oversized buffered upload must be refused, not collected until it times \
                 out: {error}"
            );
        }
    }

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        buffered_hits(&backend_hits),
        0,
        "the refused upload must never reach the backend"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn buffered_request_under_the_fail_closed_fallback_still_succeeds() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = budget_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start request-buffer-budget gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http1 client");

    // The ceiling is a fail-closed bound, not a new refusal: ordinary buffered
    // traffic under it is unaffected.
    let response = client
        .post(gateway.proxy_url("/buffered"))
        .header("content-type", "application/json")
        .body(json_body(1_024))
        .send()
        .await
        .expect("small buffered upload completes");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a buffered upload under the fallback must still be forwarded"
    );

    assert_eq!(
        buffered_hits(&backend_hits),
        1,
        "the accepted upload must reach the backend exactly once"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn streaming_request_is_unaffected_by_the_buffered_ceiling() {
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = budget_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start request-buffer-budget gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http1 client");

    // `/streamed` has no body-buffering plugin and no retry policy, so the
    // gateway streams it. `0 = unlimited` remains a valid STREAMING policy —
    // nothing is retained — so the identical payload that was refused above
    // must still be forwarded here. This is the regression guard against the
    // fail-closed ceiling leaking onto the streaming path.
    let response = client
        .post(gateway.proxy_url("/streamed"))
        .header("content-type", "application/json")
        .body(json_body(OVERSIZED_PAYLOAD_BYTES))
        .send()
        .await
        .expect("oversized streamed upload completes");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "the buffered ceiling must not apply to a streamed request; got {status} {body}"
    );
    assert_eq!(
        streamed_hits(&backend_hits),
        1,
        "the streamed upload must reach the backend"
    );

    gateway.shutdown();
    backend_task.abort();
}

/// Stalled uploads that would hold every block of a two-ceiling budget if each
/// one were still charged its whole ceiling before its first byte.
const STALLED_UPLOADS: usize = 4;

#[ignore]
#[tokio::test]
async fn stalled_buffered_uploads_do_not_hold_the_budget_against_other_clients() {
    // Audit finding: every buffered upload used to reserve its whole retained
    // ceiling before a byte arrived, so a client that opened as many uploads
    // as the budget holds ceilings and sent no body got every other client's
    // buffered upload refused with `503` for a whole read timeout. The budget
    // here holds exactly two ceilings.
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = budget_gateway_builder(backend_port)
        .env(
            "FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES",
            (2 * FALLBACK_BYTES).to_string(),
        )
        .spawn()
        .await
        .expect("start request-buffer-budget gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    // Each stalled upload sends its request head and a declared length within
    // the ceiling, then no body.
    let stalled_body = json_body(1_024);
    let mut stalled = Vec::with_capacity(STALLED_UPLOADS);
    for _ in 0..STALLED_UPLOADS {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", gateway.proxy_port))
            .await
            .expect("connect stalled upload");
        let head = format!(
            "POST /buffered HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n",
            stalled_body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("write stalled request head");
        stalled.push(stream);
    }
    // Give the gateway time to route the stalled requests into their buffered
    // collects. The assertions below do not depend on this: they hold whether
    // or not the collects have started.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http1 client");
    let response = client
        .post(gateway.proxy_url("/buffered"))
        .header("content-type", "application/json")
        .body(json_body(1_024))
        .send()
        .await
        .expect("complete buffered upload");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "stalled uploads that sent no body must not refuse another client's buffered \
         upload; got {status} {body}"
    );
    assert_eq!(buffered_hits(&backend_hits), 1);

    // The stalled uploads were live buffered collects all along: one that
    // finally sends its body is forwarded.
    let mut late = stalled.pop().expect("a stalled upload");
    late.write_all(stalled_body.as_bytes())
        .await
        .expect("write late body");
    let head = tokio::time::timeout(Duration::from_secs(10), read_response_head(&mut late))
        .await
        .expect("late upload answered");
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "a stalled upload that completes must be forwarded; got {head:?}"
    );
    assert_eq!(buffered_hits(&backend_hits), 2);

    drop(stalled);
    gateway.shutdown();
    backend_task.abort();
}

/// A request-body transform growth larger than the whole request-buffer
/// budget, so covering the replacement must be refused.
const TRANSFORM_PADDING_BYTES: usize = 80 * 1024;

#[ignore]
#[tokio::test]
async fn a_transform_capacity_refusal_keeps_its_503_under_a_smaller_response_limit() {
    // Sol review (round 9): the capacity refusal a request-body transform
    // triggers is the gateway-local terminal. A route response-size limit
    // smaller than its fixed body must not turn it into a `502` "Response body
    // too large" before any backend was contacted.
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = TestGateway::builder()
        .mode_file(transform_capacity_config(backend_port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env(
            "FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES",
            FALLBACK_BYTES.to_string(),
        )
        .env(
            "FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES",
            FALLBACK_BYTES.to_string(),
        )
        .spawn()
        .await
        .expect("start transform-capacity gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("http1 client");

    let response = client
        .post(gateway.proxy_url("/buffered-capacity"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("refused upload is answered");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::SERVICE_UNAVAILABLE,
        "the transform-capacity refusal must keep its gateway-local 503; got {status} {body}"
    );
    assert!(
        body.contains("Request buffering capacity exceeded"),
        "response policy must not replace the fixed capacity body: {body}"
    );
    assert_eq!(
        buffered_hits(&backend_hits),
        0,
        "the refused upload must never reach the backend"
    );

    // The refusal released its charge: an admissible upload under the same
    // response limit still succeeds.
    let response = client
        .post(gateway.proxy_url("/buffered-admissible"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("admissible upload completes");
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "an admissible upload must still be forwarded; got {status} {body}"
    );
    assert_eq!(buffered_hits(&backend_hits), 1);

    gateway.shutdown();
    backend_task.abort();
}

fn transform_capacity_config(backend_port: u16) -> String {
    let padding = "p".repeat(TRANSFORM_PADDING_BYTES);
    let mut plugin_configs = Vec::from(transform_plugins("capacity-route", padding));
    plugin_configs.extend(transform_plugins("admissible-route", "p".to_string()));
    let config = json!({
        "version": "1",
        "proxies": [
            transform_route("capacity-route", "/buffered-capacity", backend_port),
            transform_route("admissible-route", "/buffered-admissible", backend_port)
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": plugin_configs
    });
    serde_yaml::to_string(&config).expect("serialize transform-capacity config")
}

/// A buffered route whose request transformer adds `padding` to the JSON body
/// and whose strict response-size limit is smaller than any error body.
fn transform_route(id: &str, path: &str, backend_port: u16) -> serde_json::Value {
    json!({
        "id": id,
        "listen_path": path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": [
            {"plugin_config_id": format!("{id}-transform")},
            {"plugin_config_id": format!("{id}-response-limit")}
        ]
    })
}

fn transform_plugins(id: &str, padding: String) -> [serde_json::Value; 2] {
    [
        json!({
            "id": format!("{id}-transform"),
            "proxy_id": id,
            "plugin_name": "request_transformer",
            "scope": "proxy",
            "enabled": true,
            "config": {"rules": [{
                "operation": "add",
                "target": "body",
                "key": "padding",
                "value": padding
            }]}
        }),
        json!({
            "id": format!("{id}-response-limit"),
            "proxy_id": id,
            "plugin_name": "response_size_limiting",
            "scope": "proxy",
            "enabled": true,
            "config": {"max_bytes": 16, "require_buffered_check": true}
        }),
    ]
}

/// A retried upload larger than the whole request-buffer budget.
const RETRIED_UPLOAD_BYTES: usize = 100 * 1024;

#[ignore]
#[tokio::test]
async fn a_dispatch_capacity_refusal_is_never_advertised_as_gzip() {
    // Sol review (round 13): a dispatch-stage capacity refusal is a gateway
    // terminal whose body transforms are skipped, so no header hook may commit
    // a body coding for it. Retry replay buffers this PUT inside dispatch, the
    // budget refuses it, and `compression` must not label the plaintext
    // refusal `Content-Encoding: gzip` after `response_transformer` gave it a
    // compressible media type.
    let (backend_port, backend_hits, backend_task) = spawn_counting_backend().await;
    let mut gateway = TestGateway::builder()
        .mode_file(retry_compression_config(backend_port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env(
            "FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES",
            FALLBACK_BYTES.to_string(),
        )
        .env(
            "FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES",
            FALLBACK_BYTES.to_string(),
        )
        .spawn()
        .await
        .expect("start retry-compression gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let upload = vec![b'u'; RETRIED_UPLOAD_BYTES];
    let (head, body) = raw_gzip_put(gateway.proxy_port, &upload).await;
    assert!(
        head.starts_with("http/1.1 503"),
        "the retried upload must get the capacity refusal: {head}"
    );
    assert!(
        !head.contains("content-encoding"),
        "a plaintext capacity refusal must not advertise a coding: {head}"
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("Request buffering capacity exceeded"),
        "the refusal body must stay readable: {text}"
    );
    assert_eq!(buffered_hits(&backend_hits), 0);

    // The refusal released its charge: an admissible upload through the same
    // route still succeeds.
    let (head, _) = raw_gzip_put(gateway.proxy_port, b"small").await;
    assert!(head.starts_with("http/1.1 200"), "unexpected head: {head}");
    assert_eq!(buffered_hits(&backend_hits), 1);

    gateway.shutdown();
    backend_task.abort();
}

/// One raw HTTP/1.1 `PUT` that negotiates gzip, read until the gateway closes
/// the connection, so the test sees the exact wire head and body with no
/// client-side decoding. Returns the lowercased head and the body bytes.
async fn raw_gzip_put(port: u16, body: &[u8]) -> (String, Vec<u8>) {
    let head = format!(
        "PUT /buffered-retry HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept-Encoding: gzip\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect gateway");
    stream
        .write_all(head.as_bytes())
        .await
        .expect("request head");
    // The gateway may answer before it has read the whole upload.
    let _ = stream.write_all(body).await;
    let mut response = Vec::new();
    let read = stream.read_to_end(&mut response);
    let _ = tokio::time::timeout(Duration::from_secs(10), read).await;
    let end = find_header_end(&response).expect("complete response head");
    let head = String::from_utf8_lossy(&response[..end]);
    (head.to_ascii_lowercase(), response[end..].to_vec())
}

fn retry_compression_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "retry-route",
            "listen_path": "/buffered-retry",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "retry": {
                "max_retries": 1,
                "retry_on_connect_failure": true,
                "retryable_methods": ["PUT"]
            },
            "plugins": [
                {"plugin_config_id": "retry-content-type"},
                {"plugin_config_id": "retry-gzip"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "retry-content-type",
                "proxy_id": "retry-route",
                "plugin_name": "response_transformer",
                "scope": "proxy",
                "enabled": true,
                "config": {"rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "content-type",
                    "value": "application/json"
                }]}
            },
            {
                "id": "retry-gzip",
                "proxy_id": "retry-route",
                "plugin_name": "compression",
                "scope": "proxy",
                "enabled": true,
                "config": {"algorithms": ["gzip"], "min_content_length": 1}
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize retry-compression config")
}

/// Read one HTTP/1.1 response head from `stream`.
async fn read_response_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_header_end(&buf) {
            return String::from_utf8_lossy(&buf[..end]).into_owned();
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return String::from_utf8_lossy(&buf).into_owned(),
            Ok(read) => buf.extend_from_slice(&chunk[..read]),
        }
    }
}

fn budget_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(budget_config(backend_port))
        .log_level("warn")
        // Counting backend hits, so the startup capability probe must not add
        // one of its own.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        // The condition under test: a documented "unlimited" request-body
        // limit.
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        // The fail-closed fallback that must apply anyway, on the buffered
        // path only.
        .env(
            "FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES",
            FALLBACK_BYTES.to_string(),
        )
}

fn budget_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [
            {
                "id": "buffered-route",
                "listen_path": "/buffered",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": false,
                "pool_enable_http2": false,
                "plugins": [{"plugin_config_id": "bv-buffered"}]
            },
            {
                "id": "streamed-route",
                "listen_path": "/streamed",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": false,
                "pool_enable_http2": false
            }
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "bv-buffered",
            "proxy_id": "buffered-route",
            "plugin_name": "body_validator",
            "scope": "proxy",
            "enabled": true,
            "config": {"required_fields": ["name"]}
        }]
    });
    serde_yaml::to_string(&config).expect("serialize request-buffer-budget config")
}

/// `[buffered_hits, streamed_hits]`.
type RouteHits = [Arc<AtomicUsize>; 2];

fn buffered_hits(hits: &RouteHits) -> usize {
    hits[0].load(Ordering::SeqCst)
}

fn streamed_hits(hits: &RouteHits) -> usize {
    hits[1].load(Ordering::SeqCst)
}

/// Minimal HTTP/1.1 backend that drains the declared `Content-Length` before
/// answering, so a large upload is not cut off by an early response, and counts
/// per route so a streamed forward and a buffered forward stay distinguishable.
async fn spawn_counting_backend() -> (u16, RouteHits, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind counting backend");
    let port = listener.local_addr().expect("local addr").port();
    let hits: RouteHits = [Arc::default(), Arc::default()];
    let task_hits = hits.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let hits = task_hits.clone();
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
                let mut chunk = vec![0u8; 16 * 1024];

                // Read until the header block is complete.
                let header_end = loop {
                    if let Some(idx) = find_header_end(&buf) {
                        break idx;
                    }
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => buf.extend_from_slice(&chunk[..read]),
                    }
                };

                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if !name.trim().eq_ignore_ascii_case("content-length") {
                            return None;
                        }
                        value.trim().parse::<usize>().ok()
                    })
                    .unwrap_or(0);

                // Drain the declared body before answering. Chunked uploads
                // are not used by this test, so an absent Content-Length means
                // an empty body.
                while buf.len() - header_end < content_length {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => buf.extend_from_slice(&chunk[..read]),
                    }
                }

                let request_line = head.lines().next().unwrap_or_default();
                if request_line.contains(" /buffered") {
                    hits[0].fetch_add(1, Ordering::SeqCst);
                } else if request_line.contains(" /streamed") {
                    hits[1].fetch_add(1, Ordering::SeqCst);
                }

                let body = br#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, hits, task)
}

/// Index just past the end of the HTTP header block, if it is complete.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}
