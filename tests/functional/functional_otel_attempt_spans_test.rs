//! Live `otel_tracing` per-attempt CLIENT spans (issue #5864).
//!
//! A real gateway exports to an in-test OTLP/HTTP collector. Each test checks
//! that every backend attempt, retries included, produces one CLIENT span
//! parented under the request's SERVER span, and that the backend received that
//! attempt's own span as its `traceparent` parent:
//!
//! * HTTP/1.1: a `503 -> 200` status retry through the bundled HTTP client,
//!   which does not expose pooled-connection reuse, so none is reported.
//! * gRPC: connect-failure retries against a refused target (the attempt set up
//!   a connection that never came up), then two RPCs on a live target: the
//!   first establishes the pooled connection with its measured setup phases,
//!   the second rides it.
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_otel_attempt_spans -- --ignored --nocapture
//! ```

use crate::scaffolding::port_registry::TestSocket;

use crate::scaffolding::backends::{
    GrpcStep, HttpStep, MatchRpc, RequestMatcher, ScriptedGrpcBackend, ScriptedHttp1Backend,
};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_port, reserve_refused_tcp_port};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

const CONNECTION_TIMINGS: [&str; 4] = [
    "gateway.backend.connection.setup_ms",
    "gateway.backend.connection.dns_ms",
    "gateway.backend.connection.tcp_connect_ms",
    "gateway.backend.connection.tls_handshake_ms",
];

async fn start_collector() -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v1/traces"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

fn otel_plugin(collector: &wiremock::MockServer) -> Value {
    json!({
        "id": "otel-attempt-spans",
        "plugin_name": "otel_tracing",
        "scope": "global",
        "enabled": true,
        "config": {
            "endpoint": format!("{}/v1/traces", collector.uri()),
            "service_name": "attempt-spans",
            "batch_size": 1,
            "flush_interval_ms": 100
        }
    })
}

/// Every span the collector has received, across export batches.
async fn received_spans(collector: &wiremock::MockServer) -> Vec<Value> {
    let requests = collector.received_requests().await.unwrap_or_default();
    let mut spans = Vec::new();
    for request in requests {
        let Ok(payload) = request.body_json::<Value>() else {
            continue;
        };
        for resource in payload["resourceSpans"].as_array().into_iter().flatten() {
            for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
                spans.extend(scope["spans"].as_array().into_iter().flatten().cloned());
            }
        }
    }
    spans
}

/// Poll the collector until `ready` accepts its spans, or time out with the
/// spans it has.
async fn wait_for_spans(
    collector: &wiremock::MockServer,
    ready: impl Fn(&[Value]) -> bool,
) -> Vec<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let spans = received_spans(collector).await;
        if ready(&spans) || tokio::time::Instant::now() >= deadline {
            return spans;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn attr<'a>(span: &'a Value, key: &str) -> Option<&'a Value> {
    span["attributes"]
        .as_array()?
        .iter()
        .find(|attribute| attribute["key"] == key)
        .map(|attribute| &attribute["value"])
}

fn string_attr<'a>(span: &'a Value, key: &str) -> Option<&'a str> {
    attr(span, key)?["stringValue"].as_str()
}

fn int_attr(span: &Value, key: &str) -> Option<i64> {
    attr(span, key)?["intValue"].as_str()?.parse().ok()
}

fn bool_attr(span: &Value, key: &str) -> Option<bool> {
    attr(span, key)?["boolValue"].as_bool()
}

fn double_attr(span: &Value, key: &str) -> Option<f64> {
    attr(span, key)?["doubleValue"].as_f64()
}

fn in_trace<'a>(spans: &'a [Value], trace_id: &str) -> Vec<&'a Value> {
    spans
        .iter()
        .filter(|span| span["traceId"] == trace_id)
        .collect()
}

fn is_client(span: &&Value) -> bool {
    span["kind"] == 3
}

/// The CLIENT spans among `spans`, ordered by attempt number.
fn client_spans<'a>(spans: impl IntoIterator<Item = &'a Value>) -> Vec<&'a Value> {
    let mut clients: Vec<&Value> = spans.into_iter().filter(is_client).collect();
    clients.sort_by_key(|span| int_attr(span, "gateway.backend.attempt"));
    clients
}

fn server_span<'a>(spans: &[&'a Value]) -> &'a Value {
    let servers: Vec<&Value> = spans
        .iter()
        .copied()
        .filter(|span| span["kind"] == 2)
        .collect();
    assert_eq!(servers.len(), 1, "one SERVER span per request: {spans:#?}");
    servers[0]
}

/// `(trace_id, parent_span_id)` of a `traceparent` a backend received.
fn traceparent_ids(traceparent: &str) -> (String, String) {
    let fields: Vec<&str> = traceparent.split('-').collect();
    assert_eq!(fields.len(), 4, "malformed traceparent {traceparent:?}");
    assert_eq!(fields[3], "01", "the request is sampled");
    (fields[1].to_string(), fields[2].to_string())
}

fn http1_response(status: u16, reason: &str, body: &[u8]) -> Vec<HttpStep> {
    vec![
        HttpStep::ExpectRequest(RequestMatcher::method_path("GET", "/recover")),
        HttpStep::RespondStatus {
            status,
            reason: reason.into(),
        },
        HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: body.len().to_string(),
        },
        HttpStep::RespondHeader {
            name: "Connection".into(),
            value: "close".into(),
        },
        HttpStep::RespondBodyChunk(body.to_vec()),
        HttpStep::RespondBodyEnd,
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn http1_status_retry_exports_one_client_span_per_attempt() {
    let collector = start_collector().await;
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .connection_scripts([
            http1_response(503, "Service Unavailable", b"retry"),
            http1_response(200, "OK", b"recovered"),
        ])
        .spawn()
        .expect("spawn backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "otel-attempts-h1",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "retry": {
                "max_retries": 1,
                "retryable_status_codes": [503],
                "retryable_methods": ["GET"],
                "retry_on_connect_failure": false,
                "backoff": {"fixed": {"delay_ms": 10}}
            }
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [otel_plugin(&collector)],
    });
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("yaml"))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = harness.http_client().expect("client");
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        client.get(&harness.proxy_url("/api/recover")),
    )
    .await
    .expect("status retry must be bounded")
    .expect("gateway response");
    assert_eq!(response.status.as_u16(), 200, "response={response:?}");

    let requests = backend.received_requests().await;
    assert_eq!(
        requests.len(),
        2,
        "503 -> 200 makes two attempts: {requests:?}"
    );
    let parents: Vec<(String, String)> = requests
        .iter()
        .map(|request| traceparent_ids(request.header("traceparent").expect("traceparent")))
        .collect();
    let trace_id = parents[0].0.clone();
    assert_eq!(parents[1].0, trace_id, "both attempts belong to one trace");
    assert_ne!(parents[0].1, parents[1].1, "each attempt has its own span");

    let spans = wait_for_spans(&collector, |spans| in_trace(spans, &trace_id).len() >= 3).await;
    let trace = in_trace(&spans, &trace_id);
    assert_eq!(
        trace.len(),
        3,
        "one SERVER and two CLIENT spans: {trace:#?}"
    );
    let server = server_span(&trace);
    let server_span_id = server["spanId"].as_str().expect("server span id");
    assert!(!parents.iter().any(|(_, parent)| parent == server_span_id));
    // The client still sees the gateway SERVER span's context.
    let echoed = response.headers.get("traceparent").expect("echo");
    assert_eq!(
        traceparent_ids(echoed.to_str().expect("ascii")).1,
        server_span_id
    );

    let clients = client_spans(trace.iter().copied());
    assert_eq!(clients.len(), 2);
    for (index, (span, (_, parent))) in clients.iter().zip(&parents).enumerate() {
        assert_eq!(
            span["spanId"],
            parent.as_str(),
            "attempt {} parent",
            index + 1
        );
        assert_eq!(span["parentSpanId"], server_span_id);
        assert_eq!(
            int_attr(span, "gateway.backend.attempt"),
            Some(index as i64 + 1)
        );
        assert_eq!(string_attr(span, "http.request.method"), Some("GET"));
        assert_eq!(string_attr(span, "server.address"), Some("127.0.0.1"));
        assert_eq!(int_attr(span, "server.port"), Some(i64::from(backend_port)));
        assert!(
            attr(span, "gateway.backend.connection.reused").is_none(),
            "the bundled HTTP/1.1 client does not expose reuse, so none is reported"
        );
    }
    let first = clients[0];
    assert_eq!(int_attr(first, "http.response.status_code"), Some(503));
    assert_eq!(string_attr(first, "error.type"), Some("503"));
    assert_eq!(int_attr(first, "http.request.resend_count"), None);
    let second = clients[1];
    assert_eq!(int_attr(second, "http.response.status_code"), Some(200));
    assert_eq!(string_attr(second, "error.type"), None);
    assert_eq!(int_attr(second, "http.request.resend_count"), Some(1));
    assert_eq!(
        string_attr(second, "gateway.backend.retry_reason"),
        Some("http_status")
    );
}

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Send one unary gRPC call through the gateway and return its `grpc-status`.
async fn send_grpc(gateway_addr: &str, path: &str) -> String {
    let addr: SocketAddr = gateway_addr.parse().expect("gateway address");
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect gateway");
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(grpc_frame(b"ping"))))
        .expect("request");
    let response = sender.send_request(request).await.expect("response");
    assert_eq!(response.status(), http::StatusCode::OK);
    if let Some(status) = response.headers().get("grpc-status") {
        return status.to_str().expect("ascii").to_string();
    }
    let collected = response.into_body().collect().await.expect("body");
    collected
        .trailers()
        .and_then(|trailers| trailers.get("grpc-status"))
        .and_then(|status| status.to_str().ok())
        .expect("grpc-status trailer")
        .to_string()
}

fn unary_rpc() -> [GrpcStep; 4] {
    [
        GrpcStep::AcceptRpc(MatchRpc::any()),
        GrpcStep::SendInitialHeaders,
        GrpcStep::RespondMessage(Bytes::from_static(b"pong")),
        GrpcStep::RespondStatus {
            code: 0,
            message: "",
        },
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn grpc_attempt_spans_cover_connect_retries_and_pooled_connection_reuse() {
    let collector = start_collector().await;
    let refused = reserve_refused_tcp_port().expect("reserve refused backend port");
    let refused_port = refused.port;
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = listener.local_addr().expect("backend address").port();
    // Both RPCs ride the one connection the first establishes.
    let backend = ScriptedGrpcBackend::builder_plain(listener)
        .steps(unary_rpc())
        .steps(unary_rpc())
        .spawn()
        .expect("spawn backend");

    let config = json!({
        "version": "1",
        "proxies": [
            {
                "id": "otel-attempts-grpc-down",
                "listen_path": "/down",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": refused_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 1000,
                "retry": {
                    "max_retries": 2,
                    "retryable_status_codes": [],
                    "retryable_methods": [],
                    "retry_on_connect_failure": true,
                    "backoff": {"fixed": {"delay_ms": 10}}
                }
            },
            {
                "id": "otel-attempts-grpc",
                "listen_path": "/grpc",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true
            }
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [otel_plugin(&collector)],
    });
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("yaml"))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gateway_addr = harness
        .proxy_base_url()
        .trim_start_matches("http://")
        .to_string();

    assert_eq!(
        send_grpc(&gateway_addr, "/down/ferrum.Echo/Ping").await,
        "14",
        "every attempt against the refused target fails"
    );
    for _ in 0..2 {
        assert_eq!(
            send_grpc(&gateway_addr, "/grpc/ferrum.Echo/Ping").await,
            "0"
        );
    }
    backend.assert_no_step_errors().await;
    let streams = backend.received_streams().await;
    assert_eq!(streams.len(), 2);
    let live: Vec<(String, String)> = streams
        .iter()
        .map(|stream| traceparent_ids(stream.header("traceparent").expect("traceparent")))
        .collect();

    let spans = wait_for_spans(&collector, |spans| {
        let down = client_spans(spans)
            .into_iter()
            .filter(|span| int_attr(span, "server.port") == Some(i64::from(refused_port)))
            .count();
        down >= 3 && live.iter().all(|(t, _)| in_trace(spans, t).len() >= 2)
    })
    .await;

    // Connect-failure retries: one CLIENT span per attempt under one SERVER span.
    let down: Vec<&Value> = client_spans(&spans)
        .into_iter()
        .filter(|span| int_attr(span, "server.port") == Some(i64::from(refused_port)))
        .collect();
    assert_eq!(down.len(), 3, "1 attempt + 2 retries: {down:#?}");
    let down_trace = down[0]["traceId"].as_str().expect("trace id");
    let down_server = server_span(&in_trace(&spans, down_trace));
    for (index, span) in down.iter().enumerate() {
        assert_eq!(span["traceId"], down_trace);
        assert_eq!(span["parentSpanId"], down_server["spanId"]);
        assert_eq!(
            int_attr(span, "gateway.backend.attempt"),
            Some(index as i64 + 1)
        );
        assert_eq!(
            int_attr(span, "http.request.resend_count"),
            (index > 0).then_some(index as i64)
        );
        assert!(string_attr(span, "error.type").is_some(), "{span:#}");
        assert_eq!(span["status"]["code"], 2);
        assert_ne!(
            bool_attr(span, "gateway.backend.connection.reused"),
            Some(true),
            "no connection to the refused target ever existed to reuse"
        );
        assert!(double_attr(span, "gateway.backend.connection.setup_ms").is_none());
        if index > 0 {
            assert_eq!(
                string_attr(span, "gateway.backend.retry_reason"),
                string_attr(down[index - 1], "error.type"),
                "a retry names the failure that caused it"
            );
        }
    }
    assert_eq!(
        bool_attr(down[0], "gateway.backend.connection.reused"),
        Some(false),
        "the first attempt tried to set up a connection"
    );
    assert!(double_attr(down[0], "gateway.backend.connection.dns_ms").is_some());

    // Live target: the first RPC sets up the pooled connection, the second
    // reuses it. Each backend stream's parent is its attempt span.
    let mut attempts = Vec::new();
    for (trace_id, parent) in &live {
        let trace = in_trace(&spans, trace_id);
        let server = server_span(&trace);
        let clients = client_spans(trace.iter().copied());
        assert_eq!(clients.len(), 1, "one attempt per RPC: {trace:#?}");
        let attempt = clients[0];
        assert_eq!(attempt["spanId"], parent.as_str());
        assert_eq!(attempt["parentSpanId"], server["spanId"]);
        assert_eq!(int_attr(attempt, "gateway.backend.attempt"), Some(1));
        assert_eq!(
            int_attr(attempt, "server.port"),
            Some(i64::from(backend_port))
        );
        assert_eq!(string_attr(attempt, "error.type"), None);
        attempts.push(attempt);
    }
    let setup = attempts[0];
    assert_eq!(
        bool_attr(setup, "gateway.backend.connection.reused"),
        Some(false)
    );
    for key in [
        "gateway.backend.connection.setup_ms",
        "gateway.backend.connection.dns_ms",
        "gateway.backend.connection.tcp_connect_ms",
    ] {
        let value = double_attr(setup, key).unwrap_or_else(|| panic!("{key} missing: {setup:#}"));
        assert!(value >= 0.0, "{key}={value}");
    }
    assert!(
        attr(setup, "gateway.backend.connection.tls_handshake_ms").is_none(),
        "an h2c connection performs no TLS handshake, so none is reported"
    );
    let reused = attempts[1];
    assert_eq!(
        bool_attr(reused, "gateway.backend.connection.reused"),
        Some(true)
    );
    for key in CONNECTION_TIMINGS {
        assert!(
            attr(reused, key).is_none(),
            "a reused connection reports {key}"
        );
    }

    drop(refused);
}
