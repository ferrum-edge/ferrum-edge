//! Live `otel_tracing` per-attempt CLIENT spans on the HTTP/3 and WebSocket
//! dispatch paths (issues #5867 and #5875).
//!
//! A real gateway exports to an in-test OTLP/HTTP collector, and each scripted
//! backend records the `traceparent` it received. Every backend attempt must
//! export exactly one CLIENT span, parented under the request's SERVER span,
//! and the backend must receive that attempt's own span as its parent:
//!
//! * HTTP/3, header-refined dispatch: a response-body plugin makes the H3
//!   frontend decide buffering from the backend's response head, so the first
//!   attempt is dispatched by the refinement step and its `503` retry by the
//!   buffered loop. Both attempts are exported.
//! * HTTP/3, streamed request body: a single streamed attempt, ended at its
//!   response head.
//! * HTTP/3 bridged to an HTTP/1.1 backend: a `503 -> 200` status retry
//!   through the bridge's prebuffered retry loop exports one span per attempt.
//! * WebSocket: an HTTP/1.1 upgrade, whose attempt ends with the backend's
//!   `101`, and an upgrade the gateway's dial policy refuses, which reached no
//!   backend and exports no attempt span.
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_otel_attempt_spans_protocols -- --ignored --nocapture
//! ```

use super::functional_otel_attempt_spans_test::{
    client_spans, in_trace, int_attr, otel_plugin, received_spans, start_collector, string_attr,
    traceparent_ids, wait_for_spans,
};
use crate::scaffolding::backends::{
    H3Step, H3TlsConfig, ScriptedH3Backend, ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http3Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{
    BIND_DROP_SPAWN_ATTEMPTS, reserve_colocated_tcp_udp, reserve_port, reserve_refused_tcp_port,
};
use crate::scaffolding::to_file_mode_yaml;
use bytes::Bytes;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The `traceparent` header of a request an HTTP/3 backend recorded.
fn h3_traceparent(headers: &[(String, String)]) -> String {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("traceparent"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(values.len(), 1, "one traceparent per request: {headers:?}");
    values[0].to_string()
}

/// The SERVER spans among `spans`.
fn server_spans<'a>(spans: &[&'a Value]) -> Vec<&'a Value> {
    spans
        .iter()
        .copied()
        .filter(|span| span["kind"] == 2)
        .collect()
}

/// Assert `clients` are one CLIENT span per backend request, in attempt order,
/// each the parent the matching backend request received and each a child of
/// the request's SERVER span.
fn assert_attempts_parent_backends(
    clients: &[&Value],
    backend_parents: &[(String, String)],
    server_span_ids: &[&str],
) {
    assert_eq!(
        clients.len(),
        backend_parents.len(),
        "one CLIENT span per backend attempt: {clients:#?}"
    );
    for (index, (span, (_, parent))) in clients.iter().zip(backend_parents).enumerate() {
        assert_eq!(
            span["spanId"],
            parent.as_str(),
            "attempt {} is the backend's parent",
            index + 1
        );
        assert_eq!(
            int_attr(span, "gateway.backend.attempt"),
            Some(index as i64 + 1)
        );
        let span_parent = span["parentSpanId"].as_str().expect("attempt parent");
        assert!(
            server_span_ids.contains(&span_parent),
            "attempt {} is a child of the SERVER span: {span:#?}",
            index + 1
        );
    }
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("otel-attempt-spans-h3-gateway").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = scratch.join("gw.cert.pem");
    let key_path = scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Spawn an HTTP/3 gateway on a freshly reserved HTTPS/QUIC port. The port is
/// pinned by env for one spawn, so a lost bind race retries the whole spawn on
/// a fresh port.
async fn spawn_h3_gateway(yaml: String) -> (GatewayHarness, u16) {
    let mut last_error = None;
    for attempt in 1..=BIND_DROP_SPAWN_ATTEMPTS {
        let https_port = reserve_port()
            .await
            .expect("reserve https port")
            .drop_and_take_port();
        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        let spawned = GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("info")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match spawned {
            Ok(harness) => {
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(error) => {
                eprintln!(
                    "H3 gateway spawn attempt {attempt}/{BIND_DROP_SPAWN_ATTEMPTS} failed \
                     (https_port={https_port}): {error}"
                );
                last_error = Some(error.to_string());
            }
        }
    }
    panic!(
        "H3 gateway failed to start: {}",
        last_error.unwrap_or_else(|| "no startup error recorded".to_string())
    );
}

/// An HTTP/3-capable backend: `h3_steps` on QUIC, plus a TLS listener on the
/// same TCP port for the gateway's capability probe.
async fn spawn_h3_backend(h3_steps: Vec<H3Step>) -> (ScriptedH3Backend, u16) {
    let ca = TestCa::new("otel-attempt-spans-h3-backend").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp, udp) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp.port;
    let tls_backend = ScriptedTlsBackend::builder(
        tcp.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls backend");
    Box::leak(Box::new(tls_backend));
    let h3_backend = ScriptedH3Backend::builder(udp.into_socket(), H3TlsConfig::new(cert, key))
        .steps(h3_steps)
        .spawn()
        .expect("spawn h3 backend");
    (h3_backend, backend_port)
}

/// Wait until the capability probe proves the backend speaks HTTP/3, so the
/// request takes the native HTTP/3 dispatch.
async fn wait_for_native_h3(harness: &GatewayHarness) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let body = harness
            .get_admin_json("/backend-capabilities")
            .await
            .expect("backend capabilities");
        if body["entries"][0]["plain_http"]["h3"].as_str() == Some("supported") {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the backend was never classified h3=supported: {body:#}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn h3_config(
    collector: &wiremock::MockServer,
    backend_port: u16,
    retry: Option<Value>,
    extra_plugins: Vec<Value>,
) -> String {
    let mut proxy = json!({
        "id": "otel-attempts-h3",
        "listen_path": "/api",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "backend_tls_verify_server_cert": false
    });
    if let Some(retry) = retry {
        proxy["retry"] = retry;
    }
    let mut plugins = vec![otel_plugin(collector)];
    plugins.extend(extra_plugins);
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": plugins,
    });
    to_file_mode_yaml(&config)
}

fn unavailable_h3_response() -> H3Step {
    H3Step::RespondHeadersEndStream(vec![
        (":status", "503".to_string()),
        ("content-length", "0".to_string()),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_refined_dispatch_and_its_retry_each_export_a_client_span() {
    let collector = start_collector().await;
    // Every attempt answers `503`, on one pooled QUIC connection or a new
    // one, so the request makes exactly two attempts either way.
    let (h3_backend, backend_port) = spawn_h3_backend(vec![
        H3Step::AcceptStream,
        unavailable_h3_response(),
        H3Step::AcceptStream,
        unavailable_h3_response(),
        H3Step::StallFor(Duration::from_millis(200)),
    ])
    .await;
    // A response-body transform under retries decides buffering from the
    // backend's response head: the first attempt is dispatched by that
    // header-refinement step, and its retry by the buffered retry loop.
    let transformer = json!({
        "id": "otel-attempts-h3-body-rule",
        "plugin_name": "response_transformer",
        "scope": "global",
        "enabled": true,
        "config": {
            "rules": [{"operation": "add", "target": "body", "key": "gateway", "value": "h3"}]
        }
    });
    let retry = json!({
        "max_retries": 1,
        "retryable_status_codes": [503],
        "retryable_methods": ["GET"],
        "retry_on_connect_failure": false,
        "backoff": {"fixed": {"delay_ms": 10}}
    });
    let config = h3_config(&collector, backend_port, Some(retry), vec![transformer]);
    let (harness, https_port) = spawn_h3_gateway(config).await;
    wait_for_native_h3(&harness).await;

    let client = Http3Client::insecure().expect("h3 client");
    let response = timeout(
        IO_TIMEOUT,
        client.get(&format!("https://127.0.0.1:{https_port}/api/recover")),
    )
    .await
    .expect("the retried request must be bounded")
    .unwrap_or_else(|error| {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!("h3 request failed: {error}\n--- logs ---\n{logs}");
    });

    let parents: Vec<(String, String)> = h3_backend
        .received_requests()
        .await
        .iter()
        .filter(|request| request.path == "/recover")
        .map(|request| traceparent_ids(&h3_traceparent(&request.headers)))
        .collect();
    assert_eq!(
        parents.len(),
        2,
        "503 -> 503 makes two attempts; response={response:?}"
    );
    let trace_id = parents[0].0.clone();
    assert_eq!(parents[1].0, trace_id, "both attempts belong to one trace");
    assert_ne!(parents[0].1, parents[1].1, "each attempt has its own span");

    let spans = wait_for_spans(&collector, |spans| in_trace(spans, &trace_id).len() >= 3).await;
    let trace = in_trace(&spans, &trace_id);
    let servers = server_spans(&trace);
    assert_eq!(servers.len(), 1, "one SERVER span: {trace:#?}");
    let server_span_id = servers[0]["spanId"].as_str().expect("server span id");
    assert!(!parents.iter().any(|(_, parent)| parent == server_span_id));

    // Before issue #5867 the refinement step's attempt was counted but not
    // exported: only the retry's span existed, numbered `2`.
    let clients = client_spans(trace.iter().copied());
    assert_attempts_parent_backends(&clients, &parents, &[server_span_id]);
    for span in &clients {
        assert_eq!(int_attr(span, "http.response.status_code"), Some(503));
        assert_eq!(string_attr(span, "error.type"), Some("503"));
    }
    assert_eq!(
        string_attr(clients[1], "gateway.backend.retry_reason"),
        Some("http_status")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_streamed_request_body_exports_its_client_span() {
    let collector = start_collector().await;
    let (h3_backend, backend_port) = spawn_h3_backend(vec![
        H3Step::AcceptStream,
        // The upload is streamed: the backend reads it before answering.
        H3Step::ReadRequestData,
        H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/plain".to_string()),
            ("content-length", "2".to_string()),
        ]),
        H3Step::RespondData(Bytes::from_static(b"ok")),
        H3Step::StallFor(Duration::from_millis(200)),
    ])
    .await;
    // No retry and no body plugin: the H3 frontend streams the request body.
    let config = h3_config(&collector, backend_port, None, Vec::new());
    let (harness, https_port) = spawn_h3_gateway(config).await;
    wait_for_native_h3(&harness).await;

    let client = Http3Client::insecure().expect("h3 client");
    let response = timeout(
        IO_TIMEOUT,
        client.post_bytes(
            &format!("https://127.0.0.1:{https_port}/api/upload"),
            Bytes::from_static(b"streamed-upload"),
        ),
    )
    .await
    .expect("the streamed upload must be bounded")
    .unwrap_or_else(|error| {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!("h3 upload failed: {error}\n--- logs ---\n{logs}");
    });
    assert_eq!(response.status.as_u16(), 200, "response={response:?}");
    assert_eq!(&response.body_bytes[..], b"ok");

    let uploads: Vec<_> = h3_backend
        .received_requests()
        .await
        .into_iter()
        .filter(|request| request.path == "/upload")
        .collect();
    assert_eq!(uploads.len(), 1, "one streamed attempt: {uploads:?}");
    assert!(
        !uploads[0].body.is_empty(),
        "the upload reached the backend"
    );
    let parents = [traceparent_ids(&h3_traceparent(&uploads[0].headers))];
    let trace_id = parents[0].0.clone();

    let spans = wait_for_spans(&collector, |spans| in_trace(spans, &trace_id).len() >= 2).await;
    let trace = in_trace(&spans, &trace_id);
    let servers = server_spans(&trace);
    assert_eq!(servers.len(), 1, "one SERVER span: {trace:#?}");
    let server_span_id = servers[0]["spanId"].as_str().expect("server span id");

    // Before issue #5867 the streamed attempt kept the SERVER span as the
    // backend's parent and exported nothing.
    let clients = client_spans(trace.iter().copied());
    assert_attempts_parent_backends(&clients, &parents, &[server_span_id]);
    let attempt = clients[0];
    assert_eq!(int_attr(attempt, "http.response.status_code"), Some(200));
    assert_eq!(string_attr(attempt, "error.type"), None);
    assert_eq!(string_attr(attempt, "http.request.method"), Some("POST"));
}

async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            return Ok(String::from_utf8_lossy(&buf[..end + 4]).into_owned());
        }
        if buf.len() > 16 * 1024 {
            return Err(std::io::Error::other("head too large"));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(field, _)| field.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

/// A scripted WebSocket backend: it answers only a `GET /ws` upgrade (so a
/// capability probe cannot consume it), records each upgrade's `traceparent`
/// values, and then holds the session until the peer closes it.
async fn spawn_ws_backend() -> (u16, Arc<Mutex<Vec<Vec<String>>>>) {
    let listener = reserve_port().await.expect("reserve port").into_listener();
    let port = listener.local_addr().expect("backend addr").port();
    let upgrades: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&upgrades);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(Ok(head)) = timeout(IO_TIMEOUT, read_head(&mut stream)).await else {
                    return;
                };
                if !head.starts_with("GET /ws ") {
                    return;
                }
                let Some(key) = header_values(&head, "sec-websocket-key").first().copied() else {
                    return;
                };
                let traceparents: Vec<String> = header_values(&head, "traceparent")
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                if let Ok(mut upgrades) = recorded.lock() {
                    upgrades.push(traceparents);
                }
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                    derive_accept_key(key.as_bytes())
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                let mut sink = [0u8; 1024];
                while matches!(stream.read(&mut sink).await, Ok(read) if read > 0) {}
            });
        }
    });
    (port, upgrades)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn websocket_upgrade_exports_one_client_span_for_its_backend_attempt() {
    let collector = start_collector().await;
    let (backend_port, upgrades) = spawn_ws_backend().await;
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "otel-attempts-ws",
            "listen_path": "/ws",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [otel_plugin(&collector)],
    });
    let harness = GatewayHarness::builder()
        // No binary-mode capability probe against the scripted backend.
        .mode_in_process()
        .file_config(to_file_mode_yaml(&config))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let proxy_port: u16 = harness
        .proxy_base_url()
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .expect("proxy port");

    let mut client = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect gateway");
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{proxy_port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("send upgrade");
    let head = timeout(IO_TIMEOUT, read_head(&mut client))
        .await
        .expect("upgrade response in time")
        .expect("read upgrade response");
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "the upgrade must succeed: {head}"
    );

    let recorded = upgrades.lock().expect("upgrades").clone();
    assert_eq!(recorded.len(), 1, "one backend upgrade: {recorded:?}");
    assert_eq!(
        recorded[0].len(),
        1,
        "the upgrade carries one traceparent: {recorded:?}"
    );
    let parents = [traceparent_ids(&recorded[0][0])];
    let trace_id = parents[0].0.clone();
    // Ending the session lets the gateway log the upgrade's SERVER spans.
    drop(client);

    let spans = wait_for_spans(&collector, |spans| {
        let trace = in_trace(spans, &trace_id);
        !server_spans(&trace).is_empty() && !client_spans(trace.iter().copied()).is_empty()
    })
    .await;
    let trace = in_trace(&spans, &trace_id);
    let servers = server_spans(&trace);
    assert!(!servers.is_empty(), "the handshake SERVER span: {trace:#?}");
    let server_span_ids: Vec<&str> = servers
        .iter()
        .filter_map(|span| span["spanId"].as_str())
        .collect();
    assert!(
        !server_span_ids.contains(&parents[0].1.as_str()),
        "the backend's parent is the attempt span, not the SERVER span"
    );

    // Before issue #5867 the upgrade kept the SERVER span as the backend's
    // parent and exported nothing.
    let clients = client_spans(trace.iter().copied());
    assert_attempts_parent_backends(&clients, &parents, &server_span_ids);
    let attempt = clients[0];
    assert_eq!(int_attr(attempt, "http.response.status_code"), Some(101));
    assert_eq!(string_attr(attempt, "error.type"), None);
    assert_eq!(string_attr(attempt, "http.request.method"), Some("GET"));
}

/// A scripted HTTP/1.1 backend for the HTTP/3 bridge. It answers only
/// `GET /recover` (so the gateway's startup capability probe cannot use up a
/// scripted answer), `503` first and `200` after, one request per connection,
/// and records each answered request's `traceparent` values.
async fn spawn_recovering_http1_backend() -> (u16, Arc<Mutex<Vec<Vec<String>>>>) {
    let listener = reserve_port().await.expect("reserve port").into_listener();
    let port = listener.local_addr().expect("backend addr").port();
    let requests: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let Ok(Ok(head)) = timeout(IO_TIMEOUT, read_head(&mut stream)).await else {
                    return;
                };
                if !head.starts_with("GET /recover ") {
                    return;
                }
                let traceparents: Vec<String> = header_values(&head, "traceparent")
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                let answered = match recorded.lock() {
                    Ok(mut requests) => {
                        requests.push(traceparents);
                        requests.len()
                    }
                    Err(_) => return,
                };
                let response: &[u8] = if answered == 1 {
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 5\r\nConnection: close\r\n\r\nretry"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrecovered"
                };
                if stream.write_all(response).await.is_ok() {
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    (port, requests)
}

/// The `traceparent` values each answered backend request carried.
fn recorded_traceparents(requests: &Mutex<Vec<Vec<String>>>) -> Vec<Vec<String>> {
    requests
        .lock()
        .map(|requests| requests.clone())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_plain_bridge_retry_exports_one_client_span_per_attempt() {
    let collector = start_collector().await;
    let (backend_port, requests) = spawn_recovering_http1_backend().await;
    // An `http` backend never takes native HTTP/3 dispatch, so the HTTP/3
    // frontend bridges the request to HTTP/1.1, and a bodiless GET takes the
    // bridge's prebuffered retry loop.
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "otel-attempts-h3-plain",
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
    let (harness, https_port) = spawn_h3_gateway(to_file_mode_yaml(&config)).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/recover");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let response = loop {
        let outcome = timeout(IO_TIMEOUT, client.get(&url)).await;
        if let Ok(Ok(response)) = outcome {
            break response;
        }
        // The QUIC listener may still be coming up: retry only while no
        // request has reached the backend.
        let retryable =
            tokio::time::Instant::now() < deadline && recorded_traceparents(&requests).is_empty();
        if !retryable {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!("h3 request failed: {outcome:?}\n--- logs ---\n{logs}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(response.status.as_u16(), 200, "response={response:?}");
    assert_eq!(&response.body_bytes[..], b"recovered");

    let recorded = recorded_traceparents(&requests);
    assert_eq!(
        recorded.len(),
        2,
        "503 -> 200 makes two attempts: {recorded:?}"
    );
    let parents: Vec<(String, String)> = recorded
        .iter()
        .map(|traceparents| {
            assert_eq!(
                traceparents.len(),
                1,
                "one traceparent per attempt: {recorded:?}"
            );
            traceparent_ids(&traceparents[0])
        })
        .collect();
    let trace_id = parents[0].0.clone();
    assert_eq!(parents[1].0, trace_id, "both attempts belong to one trace");
    assert_ne!(parents[0].1, parents[1].1, "each attempt has its own span");

    let spans = wait_for_spans(&collector, |spans| in_trace(spans, &trace_id).len() >= 3).await;
    let trace = in_trace(&spans, &trace_id);
    let servers = server_spans(&trace);
    assert_eq!(servers.len(), 1, "one SERVER span: {trace:#?}");
    let server_span_id = servers[0]["spanId"].as_str().expect("server span id");
    assert!(!parents.iter().any(|(_, parent)| parent == server_span_id));

    // Before issue #5875 the bridge handed every attempt the SERVER span as its
    // parent and exported no attempt span.
    let clients = client_spans(trace.iter().copied());
    assert_attempts_parent_backends(&clients, &parents, &[server_span_id]);
    assert_eq!(int_attr(clients[0], "http.response.status_code"), Some(503));
    assert_eq!(string_attr(clients[0], "error.type"), Some("503"));
    assert_eq!(int_attr(clients[1], "http.response.status_code"), Some(200));
    assert_eq!(string_attr(clients[1], "error.type"), None);
    assert_eq!(
        string_attr(clients[1], "gateway.backend.retry_reason"),
        Some("http_status")
    );
    for span in &clients {
        assert_eq!(string_attr(span, "http.request.method"), Some("GET"));
        assert_eq!(int_attr(span, "server.port"), Some(i64::from(backend_port)));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn websocket_upgrade_refused_by_dial_policy_exports_no_client_span() {
    let collector = start_collector().await;
    // Never dialed: the dial policy refuses the upgrade before any connection.
    let refused = reserve_refused_tcp_port().expect("reserve refused backend port");
    // Trust the client's trace context, so the refused upgrade's spans are
    // found by the trace the client names.
    let mut otel = otel_plugin(&collector);
    otel["config"]["trace_context_trust"] = json!("trusted");
    // The upstream's backend TLS SNI override is one the WebSocket transport
    // cannot apply, so the gateway refuses the dial by policy (issue #2416).
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "otel-attempts-ws-refused",
            "listen_path": "/ws",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": refused.port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000,
            "backend_tls_verify_server_cert": false,
            "upstream_id": "otel-attempts-ws-sni"
        }],
        "consumers": [],
        "upstreams": [{
            "id": "otel-attempts-ws-sni",
            "name": "WebSocket SNI upstream",
            "algorithm": "round_robin",
            "backend_tls_sni": "backend.example.com",
            "targets": [{"host": "127.0.0.1", "port": refused.port, "weight": 1}]
        }],
        "plugin_configs": [otel],
    });
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(to_file_mode_yaml(&config))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let proxy_port: u16 = harness
        .proxy_base_url()
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .expect("proxy port");

    let trace_id = "5875feedfacecafe5875feedfacecafe";
    let mut client = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect gateway");
    let request = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{proxy_port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\ntraceparent: 00-{trace_id}-00f067aa0ba902b7-01\r\n\r\n"
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("send upgrade");
    let head = timeout(IO_TIMEOUT, read_head(&mut client))
        .await
        .expect("upgrade response in time")
        .expect("read upgrade response");
    assert!(
        head.starts_with("HTTP/1.1 502"),
        "the refused upgrade is still answered with a 502: {head}"
    );
    drop(client);

    let spans = wait_for_spans(&collector, |spans| {
        !server_spans(&in_trace(spans, trace_id)).is_empty()
    })
    .await;
    assert!(
        !server_spans(&in_trace(&spans, trace_id)).is_empty(),
        "the refused upgrade's SERVER span: {spans:#?}"
    );
    // An attempt span is exported when its attempt is recorded, before the
    // SERVER span; allow a later export batch to land before the check.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let spans = received_spans(&collector).await;
    // Before issue #5875 the refusal ran inside the attempt's scope and was
    // exported as a `dispatch_policy_rejected` attempt that reached no backend.
    let clients = client_spans(in_trace(&spans, trace_id));
    assert!(
        clients.is_empty(),
        "a dial the gateway refused by policy exports no CLIENT span: {clients:#?}"
    );
}
