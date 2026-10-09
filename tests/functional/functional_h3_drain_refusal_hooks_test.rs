//! Issue #6022: on-the-wire proof that HTTP/3 request-body drain refusals
//! commit through the shared reject path.
//!
//! #6039 routed the native H3 drains' `413` arms and the gRPC bridge drain's
//! capacity and oversize refusals through the reject-path `after_proxy` hooks,
//! the committed-response hooks, and the transaction log. Its tests guard the
//! source structure. These spawn the real binary and check the client-visible
//! and logged result instead:
//!
//! * a reject-path `after_proxy` hook (a global `response_transformer` adding
//!   `x-reject-hook`) shaped the refusal the H3 client received, and
//! * `stdout_logging` wrote the rejected request with
//!   `rejection_phase = "on_final_request_body"`.
//!
//! Covered drains: the frontend's cross-protocol drain (H1 backend), its
//! native-H3 drain (H3 backend), and the buffered gRPC bridge drain (oversize
//! and buffer capacity). The plain bridge's own drain runs only for
//! mesh-tagged targets and stays covered by the `h3_retained_upload_tests`
//! source guards.
//!
//! A charge test proves the native-H3 buffered path returns its request-buffer
//! charge before the response streams.
//!
//! A drain test proves a buffered drain reads on past a trailer section to
//! the stream's own end, so a client that resets after its trailers is
//! refused instead of dispatched as a complete upload. The last test proves
//! the same for a streamed upload over the plain bridge: the backend sees the
//! upload aborted, never completed.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_h3_drain_refusal_hooks -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::scaffolding::port_registry::TestSocket;

use crate::scaffolding::backends::{
    GrpcStep, H3Step, H3TlsConfig, MatchRpc, ScriptedGrpcBackend, ScriptedH3Backend,
    ScriptedTlsBackend, TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{Http3Client, Http3GrpcStream};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};

const PROXY_ID: &str = "h3-drain-refusal";
const UPLOAD_PATH: &str = "/api/upload";
const GRPC_PATH: &str = "/api/echo.Echo/Upload";

/// The header the global reject-path `after_proxy` hook adds.
const HOOK_HEADER: &str = "x-reject-hook";
const HOOK_VALUE: &str = "ran";

/// The phase every drain refusal is logged under.
const REJECTION_PHASE: &str = "on_final_request_body";

/// The per-request body ceiling of the oversize cases, far below the upload.
const SMALL_LIMIT: &str = "1024";
const OVERSIZED_UPLOAD_BYTES: usize = 8 * 1024;

/// One 64 KiB reservation block: the smallest request-buffer budget the
/// runtime accepts, and the whole budget in the capacity and charge cases.
const ONE_BLOCK: &str = "65536";
const ONE_BLOCK_BYTES: u64 = 65_536;

/// The canned answer of the plain backends.
const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

// ────────────────────────────────────────────────────────────────────────────
// Configuration and gateway
// ────────────────────────────────────────────────────────────────────────────

fn base_proxy(backend_scheme: &str, backend_port: u16) -> Value {
    let mut proxy = json!({
        "id": PROXY_ID,
        "listen_path": "/api",
        "backend_scheme": backend_scheme,
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "backend_connect_timeout_ms": 5000,
        "backend_read_timeout_ms": 60000,
        "backend_write_timeout_ms": 60000,
    });
    if backend_scheme == "https" {
        proxy["backend_tls_verify_server_cert"] = json!(false);
    }
    proxy
}

/// A retry policy makes the request replayable, so the gateway drains the
/// upload before dispatch instead of streaming it.
fn with_retry(mut proxy: Value) -> Value {
    proxy["retry"] = json!({"max_retries": 1, "retry_on_connect_failure": true});
    proxy
}

/// File-mode YAML for `proxy` plus the two global plugins every case observes
/// the refusal through.
fn gateway_yaml(proxy: Value, extra_plugins: Vec<Value>) -> String {
    let mut plugin_configs = vec![
        json!({
            "id": "drain-refusal-access-log",
            "plugin_name": "stdout_logging",
            "scope": "global",
            "enabled": true,
            "config": {},
        }),
        json!({
            "id": "drain-refusal-reject-hook",
            "plugin_name": "response_transformer",
            "scope": "global",
            "enabled": true,
            "config": {"rules": [{
                "operation": "add",
                "target": "header",
                "key": HOOK_HEADER,
                "value": HOOK_VALUE,
            }]},
        }),
    ];
    plugin_configs.extend(extra_plugins);
    let config = json!({
        "version": "1",
        "proxies": [proxy],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": plugin_configs,
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-drain-refusal-gw").expect("ca");
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

/// Spawn a gateway with an HTTP/3 frontend on an explicit, retried QUIC port.
/// An env-pinned QUIC port cannot be reused after a failed startup, so every
/// attempt takes a fresh port and a fresh scratch directory.
async fn spawn_h3_gateway(yaml: String, env: &[(&str, &str)]) -> (GatewayHarness, u16) {
    const STARTUP_ATTEMPTS: u32 = 3;
    let mut last_error = None;
    for attempt in 1..=STARTUP_ATTEMPTS {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.drop_and_take_port();

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        let mut builder = GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("info")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false");
        for (key, value) in env {
            builder = builder.env(*key, *value);
        }

        match builder.spawn().await {
            Ok(harness) => {
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(error) => {
                eprintln!(
                    "H3 drain-refusal harness attempt {attempt}/{STARTUP_ATTEMPTS} failed: {error}"
                );
                last_error = Some(error.to_string());
                if attempt < STARTUP_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!(
        "H3 drain-refusal harness failed after {STARTUP_ATTEMPTS} attempts: {}",
        last_error.unwrap_or_else(|| "no startup error recorded".to_string())
    );
}

fn proxy_url(https_port: u16, path: &str) -> String {
    format!("https://127.0.0.1:{https_port}{path}")
}

async fn fetch_capability_entry(harness: &GatewayHarness) -> Option<Value> {
    let body = harness.get_admin_json("/backend-capabilities").await.ok()?;
    body["entries"].as_array().cloned()?.into_iter().next()
}

/// Wait until the capability registry classifies the backend `h3=supported`,
/// so the request takes the native-H3 backend path.
async fn wait_for_h3_supported(harness: &GatewayHarness) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(entry) = fetch_capability_entry(harness).await
            && entry["plain_http"]["h3"].as_str() == Some("supported")
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the capability registry must classify the backend h3=supported so the request \
             takes the native-H3 path; logs:\n{}",
            harness.captured_combined().unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Backends
// ────────────────────────────────────────────────────────────────────────────

/// A plain HTTP/1.1 backend that answers `200` and counts the requests whose
/// request line names `path`, so a capability probe is never mistaken for a
/// forwarded upload.
async fn spawn_counting_http1_backend(
    path: &'static str,
) -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let task_hits = Arc::clone(&hits);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            let hits = Arc::clone(&task_hits);
            tokio::spawn(async move {
                let mut head: Vec<u8> = Vec::new();
                let mut buf = [0u8; 4096];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buf[..read]),
                    }
                }
                let head = String::from_utf8_lossy(&head);
                let request_line = head.lines().next().unwrap_or_default();
                if request_line.contains(path) {
                    hits.fetch_add(1, Ordering::SeqCst);
                }
                let _ = socket.write_all(OK_RESPONSE).await;
            });
        }
    });
    (port, hits, task)
}

/// A TLS gRPC backend that would answer any RPC. The refusal cases assert it
/// never receives one.
async fn spawn_grpc_backend() -> (u16, ScriptedGrpcBackend) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    let ca = TestCa::new("h3-drain-refusal-grpc-be").expect("ca");
    let (cert, key) = ca.valid().expect("backend leaf");
    let backend = ScriptedGrpcBackend::builder_tls(listener, &cert, &key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"unexpected")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn grpc backend");
    (port, backend)
}

/// A native-H3 backend running `steps`, plus the TCP+TLS sidecar on the same
/// port that answers the capability probe. Returns the backend port.
async fn spawn_native_h3_backend(name: &str, steps: Vec<H3Step>) -> (u16, ScriptedH3Backend) {
    let ca = TestCa::new(name).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;
    let probe_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(OK_RESPONSE.to_vec()))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend");
    Box::leak(Box::new(probe_backend));
    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .steps(steps)
        .spawn()
        .expect("spawn h3 backend");
    (backend_port, h3_backend)
}

// ────────────────────────────────────────────────────────────────────────────
// Client and assertions
// ────────────────────────────────────────────────────────────────────────────

/// What the H3 client received for one upload.
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Open a client-driven H3 POST stream, retrying the QUIC handshake briefly so
/// the test does not race the listener coming up.
async fn open_upload_stream(url: &str, content_type: &str) -> Http3GrpcStream {
    let client = Http3Client::insecure().expect("H3 client");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match client
            .open_request_stream_with_content_type(url, content_type, &[])
            .await
        {
            Ok(stream) => return stream,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "the H3 upload stream never opened: {error}"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}

/// POST `body` over H3 with no `Content-Length`, in 1 KiB DATA frames. A
/// refusal may stop the upload (`STOP_SENDING`) before it completes, so send
/// and finish errors are expected; the response head is not.
async fn h3_upload(url: &str, content_type: &str, body: &[u8]) -> Answer {
    let mut stream = open_upload_stream(url, content_type).await;
    for chunk in body.chunks(1024) {
        let sent = stream.send_raw_data(Bytes::copy_from_slice(chunk)).await;
        if sent.is_err() {
            break;
        }
    }
    let _ = stream.finish().await;
    let (status, headers) = stream.recv_response().await.expect("response head");
    let body = stream
        .recv_body_and_trailers()
        .await
        .map(|(body, _)| body)
        .unwrap_or_default();
    Answer {
        status,
        headers,
        body,
    }
}

/// Length-prefix a gRPC message (1-byte flag + 4-byte BE length + payload).
fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

fn assert_reject_hook_ran(answer: &Answer) {
    assert_eq!(
        answer.header(HOOK_HEADER),
        Some(HOOK_VALUE),
        "the reject-path after_proxy hook must shape the refusal; got {} {:?} {}",
        answer.status,
        answer.headers,
        answer.body_text()
    );
}

/// Wait for the transaction-log entry `stdout_logging` writes for the refusal.
async fn wait_for_rejection_log(harness: &GatewayHarness) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let logs = harness.captured_combined().unwrap_or_default();
        if let Some(entry) = logs
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
            .find(|entry| {
                let phase = entry.pointer("/metadata/rejection_phase");
                entry.get("proxy_id").and_then(Value::as_str) == Some(PROXY_ID)
                    && phase.and_then(Value::as_str) == Some(REJECTION_PHASE)
            })
        {
            return entry;
        }
        assert!(
            Instant::now() < deadline,
            "stdout_logging must log the refusal under rejection_phase {REJECTION_PHASE:?}; \
             logs:\n{logs}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The aggregate buffered-request budget from the authenticated `/overload`
/// snapshot.
async fn request_buffer_snapshot(harness: &GatewayHarness) -> Value {
    let overload = harness
        .get_admin_json("/overload")
        .await
        .expect("GET /overload");
    overload["request_buffer"].clone()
}

// ────────────────────────────────────────────────────────────────────────────
// Native H3 frontend drains
// ────────────────────────────────────────────────────────────────────────────

/// The frontend drains a replayable upload bound for an HTTP/1.1 backend
/// before the cross-protocol bridge runs. Its `413` arm commits through the
/// reject hooks and the transaction log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_cross_protocol_drain_oversize_runs_reject_hooks_and_logs() {
    let (backend_port, hits, backend_task) = spawn_counting_http1_backend(UPLOAD_PATH).await;
    let yaml = gateway_yaml(with_retry(base_proxy("http", backend_port)), Vec::new());
    let env = [("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", SMALL_LIMIT)];
    let (harness, https_port) = spawn_h3_gateway(yaml, &env).await;

    let answer = h3_upload(
        &proxy_url(https_port, UPLOAD_PATH),
        "application/octet-stream",
        &[b'u'; OVERSIZED_UPLOAD_BYTES],
    )
    .await;

    assert_eq!(
        answer.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        answer.body_text()
    );
    assert_reject_hook_ran(&answer);
    let entry = wait_for_rejection_log(&harness).await;
    assert_eq!(
        entry.get("response_status_code").and_then(Value::as_u64),
        Some(413),
        "{entry}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the refused upload must never reach the backend"
    );
    backend_task.abort();
}

/// The same drain on the native-H3 backend path: a replayable upload bound for
/// an H3-capable backend is drained before the native pool dispatches.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_native_drain_oversize_runs_reject_hooks_and_logs() {
    let (backend_port, h3_backend) = spawn_native_h3_backend(
        "h3-drain-refusal-native",
        vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![(":status", "200".to_string())]),
            H3Step::RespondData(Bytes::from_static(b"ok")),
        ],
    )
    .await;
    let yaml = gateway_yaml(with_retry(base_proxy("https", backend_port)), Vec::new());
    let env = [("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", SMALL_LIMIT)];
    let (harness, https_port) = spawn_h3_gateway(yaml, &env).await;
    wait_for_h3_supported(&harness).await;
    let requests_before = h3_backend.received_requests().await.len();

    let answer = h3_upload(
        &proxy_url(https_port, UPLOAD_PATH),
        "application/octet-stream",
        &[b'n'; OVERSIZED_UPLOAD_BYTES],
    )
    .await;

    assert_eq!(
        answer.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        answer.body_text()
    );
    assert_reject_hook_ran(&answer);
    let entry = wait_for_rejection_log(&harness).await;
    assert_eq!(
        entry.get("response_status_code").and_then(Value::as_u64),
        Some(413),
        "{entry}"
    );
    assert_eq!(
        h3_backend.received_requests().await.len(),
        requests_before,
        "the refused upload must never reach the H3 backend"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// gRPC bridge drain
// ────────────────────────────────────────────────────────────────────────────

/// A buffered response keeps a gRPC request off the streaming bridge, so the
/// buffered bridge drains the upload itself. Its oversize refusal answers
/// `RESOURCE_EXHAUSTED` through the reject hooks and the transaction log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_bridge_drain_oversize_runs_reject_hooks_and_logs() {
    let (backend_port, backend) = spawn_grpc_backend().await;
    let mut proxy = base_proxy("https", backend_port);
    proxy["response_body_mode"] = json!("buffer");
    let (harness, https_port) = spawn_h3_gateway(
        gateway_yaml(proxy, Vec::new()),
        &[("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", SMALL_LIMIT)],
    )
    .await;
    let streams_before = backend.received_stream_count();

    let answer = h3_upload(
        &proxy_url(https_port, GRPC_PATH),
        "application/grpc",
        &grpc_frame(&[b'g'; OVERSIZED_UPLOAD_BYTES]),
    )
    .await;

    assert_eq!(
        answer.status,
        StatusCode::OK,
        "gRPC errors ride on HTTP 200"
    );
    assert_eq!(
        answer.header("grpc-status"),
        Some("8"),
        "an oversized upload is RESOURCE_EXHAUSTED; got {:?}",
        answer.headers
    );
    assert_eq!(
        answer.header("grpc-message"),
        Some("Request body exceeds maximum size")
    );
    assert_reject_hook_ran(&answer);
    wait_for_rejection_log(&harness).await;
    assert_eq!(
        backend.received_stream_count(),
        streams_before,
        "the refused upload must never reach the gRPC backend"
    );
}

/// The same drain when the shared request-buffer budget cannot admit the
/// upload's retained ceiling: a 1 MiB gRPC ceiling against a one-block budget.
/// `FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES` has a 64 KiB floor, which also
/// floors the total budget; this case pins both values to that minimum.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_bridge_drain_capacity_refusal_runs_reject_hooks_and_logs() {
    let (backend_port, backend) = spawn_grpc_backend().await;
    let mut proxy = base_proxy("https", backend_port);
    proxy["response_body_mode"] = json!("buffer");
    let (harness, https_port) = spawn_h3_gateway(
        gateway_yaml(proxy, Vec::new()),
        &[
            ("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "1048576"),
            ("FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES", ONE_BLOCK),
            ("FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES", ONE_BLOCK),
        ],
    )
    .await;
    let streams_before = backend.received_stream_count();

    let answer = h3_upload(
        &proxy_url(https_port, GRPC_PATH),
        "application/grpc",
        &grpc_frame(b"ping"),
    )
    .await;

    assert_eq!(
        answer.status,
        StatusCode::OK,
        "gRPC errors ride on HTTP 200"
    );
    assert_eq!(
        answer.header("grpc-status"),
        Some("8"),
        "a buffer-capacity refusal is RESOURCE_EXHAUSTED; got {:?}",
        answer.headers
    );
    assert_eq!(
        answer.header("grpc-message"),
        Some("Request buffering capacity exceeded")
    );
    assert_reject_hook_ran(&answer);
    wait_for_rejection_log(&harness).await;
    assert_eq!(
        backend.received_stream_count(),
        streams_before,
        "the refused upload must never reach the gRPC backend"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Request-buffer charge on the native-H3 path
// ────────────────────────────────────────────────────────────────────────────

/// A buffered request body on the native-H3 path returns its request-buffer
/// charge once dispatch is done, before the response streams. The budget is
/// one block, so a charge held for the life of the response would show as
/// reserved for as long as the backend keeps the response open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn h3_native_buffered_request_releases_its_charge_before_the_response_streams() {
    let (backend_port, h3_backend) = spawn_native_h3_backend(
        "h3-drain-refusal-charge",
        vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "200".to_string()),
                ("content-type", "text/event-stream".to_string()),
            ]),
            H3Step::RespondData(Bytes::from_static(b"event: one\n\n")),
            H3Step::StallFor(Duration::from_secs(30)),
        ],
    )
    .await;
    // `body_validator` buffers a JSON upload; no retry, so the response
    // streams.
    let mut proxy = base_proxy("https", backend_port);
    proxy["plugins"] = json!([{"plugin_config_id": "drain-refusal-body-validator"}]);
    let validator = json!({
        "id": "drain-refusal-body-validator",
        "plugin_name": "body_validator",
        "scope": "proxy",
        "proxy_id": PROXY_ID,
        "enabled": true,
        "config": {"required_fields": ["name"]},
    });
    let (harness, https_port) = spawn_h3_gateway(
        gateway_yaml(proxy, vec![validator]),
        &[
            ("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", ONE_BLOCK),
            ("FERRUM_REQUEST_BUFFER_FALLBACK_MAX_BYTES", ONE_BLOCK),
            ("FERRUM_REQUEST_BUFFER_MAX_TOTAL_BYTES", ONE_BLOCK),
        ],
    )
    .await;
    wait_for_h3_supported(&harness).await;
    let url = proxy_url(https_port, UPLOAD_PATH);
    let requests_before = h3_backend.received_requests().await.len();

    // The route inspects, and therefore buffers, the upload.
    let invalid = h3_upload(&url, "application/json", br#"{"other":1}"#).await;
    assert_eq!(
        invalid.status,
        StatusCode::BAD_REQUEST,
        "body_validator must inspect the buffered upload; got {}",
        invalid.body_text()
    );
    let snapshot = request_buffer_snapshot(&harness).await;
    assert_eq!(
        snapshot["total_bytes"].as_u64(),
        Some(ONE_BLOCK_BYTES),
        "{snapshot}"
    );

    let mut stream = open_upload_stream(&url, "application/json").await;
    stream
        .send_raw_data(Bytes::from_static(br#"{"name":"charge"}"#))
        .await
        .expect("send upload");
    stream.finish().await.expect("finish upload");
    let (status, _) = stream.recv_response().await.expect("response head");
    assert_eq!(status, StatusCode::OK);
    let first = stream
        .recv_data()
        .await
        .expect("first response chunk")
        .expect("a DATA frame, not EOF");
    assert_eq!(
        &first[..],
        b"event: one\n\n",
        "the response must come from the native-H3 backend"
    );
    assert_eq!(
        h3_backend.received_requests().await.len(),
        requests_before + 1
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = request_buffer_snapshot(&harness).await;
        if snapshot["reserved_bytes"].as_u64() == Some(0) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the buffered request must return its charge before its response streams; \
             still reserved while the response is open: {snapshot}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(500), stream.recv_data())
            .await
            .is_err(),
        "the response must still be open while the charge reads released"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// End of the request stream after a trailer section
// ────────────────────────────────────────────────────────────────────────────

/// What the gateway logs when a request task ends with a stream error.
const REQUEST_ERROR_LOG: &str = "HTTP/3 request error";

fn upload_trailers() -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "x-upload-digest",
        http::HeaderValue::from_static("sha-256=done"),
    );
    trailers
}

/// Wait until the gateway's captured output contains `needle`.
async fn wait_for_log_line(harness: &GatewayHarness, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let logs = harness.captured_combined().unwrap_or_default();
        if logs.contains(needle) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the gateway must log {needle:?}; logs:\n{logs}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A trailer section ends the request body, not the request stream. A client
/// that sends its trailers and then resets the stream instead of finishing it
/// cancelled the request, so the buffered drain must read on to the stream's
/// own end and refuse the upload rather than dispatch it as complete. The
/// control upload on the same route, trailers then FIN, still reaches the
/// backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_buffered_drain_refuses_a_reset_after_the_trailer_section() {
    let (backend_port, hits, backend_task) = spawn_counting_http1_backend(UPLOAD_PATH).await;
    let yaml = gateway_yaml(with_retry(base_proxy("http", backend_port)), Vec::new());
    let (harness, https_port) = spawn_h3_gateway(yaml, &[]).await;
    let url = proxy_url(https_port, UPLOAD_PATH);

    // The pause lets the gateway read the trailer section before the reset
    // arrives: h3 surfaces a reset ahead of frames it still has buffered, which
    // would refuse the upload without exercising the end-of-stream read.
    let mut reset = open_upload_stream(&url, "application/octet-stream").await;
    reset
        .send_raw_data(Bytes::from_static(b"cancelled upload"))
        .await
        .expect("send upload");
    reset
        .send_request_trailers(upload_trailers())
        .await
        .expect("send trailers");
    tokio::time::sleep(Duration::from_millis(500)).await;
    reset.cancel_request_upload();
    wait_for_log_line(&harness, REQUEST_ERROR_LOG).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a request reset after its trailer section must never reach the backend"
    );
    drop(reset);

    let mut complete = open_upload_stream(&url, "application/octet-stream").await;
    complete
        .send_raw_data(Bytes::from_static(b"complete upload"))
        .await
        .expect("send upload");
    complete
        .send_request_trailers(upload_trailers())
        .await
        .expect("send trailers");
    complete.finish().await.expect("finish upload");
    let (status, _) = complete.recv_response().await.expect("response head");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "only the upload that ended with FIN reaches the backend"
    );
    backend_task.abort();
}

// ────────────────────────────────────────────────────────────────────────────
// Streamed upload: end of the request stream after a trailer section
// ────────────────────────────────────────────────────────────────────────────

/// How the streamed uploads one backend received ended.
#[derive(Default)]
struct StreamedUploadEnds {
    /// Request bodies that reached their terminal chunk.
    completed: AtomicUsize,
    /// Request bodies whose connection closed before the terminal chunk.
    aborted: AtomicUsize,
}

/// Whether a chunked request body has reached its terminal (last) chunk.
fn chunked_body_complete(body: &[u8]) -> bool {
    body.starts_with(b"0\r\n\r\n") || body.windows(7).any(|window| window == b"\r\n0\r\n\r\n")
}

/// A plain HTTP/1.1 backend that reads every upload to `path` to its end. The
/// uploads carry no `Content-Length`, so the gateway sends them chunked and the
/// terminal chunk is their only clean end. A body that reaches it counts as
/// completed and is answered `200`; a connection that closes first counts as
/// aborted. Requests to any other target (the capability probe) are answered
/// and not counted.
async fn spawn_streamed_upload_backend(
    path: &'static str,
) -> (u16, Arc<StreamedUploadEnds>, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let port = listener.local_addr().expect("backend addr").port();
    let ends = Arc::new(StreamedUploadEnds::default());
    let task_ends = Arc::clone(&ends);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                continue;
            };
            let ends = Arc::clone(&task_ends);
            tokio::spawn(async move {
                let mut received: Vec<u8> = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    let head_end = received.windows(4).position(|window| window == b"\r\n\r\n");
                    if let Some(at) = head_end {
                        break at + 4;
                    }
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => received.extend_from_slice(&buf[..read]),
                    }
                };
                let head = String::from_utf8_lossy(&received[..head_end]).into_owned();
                if !head.lines().next().unwrap_or_default().contains(path) {
                    let _ = socket.write_all(OK_RESPONSE).await;
                    return;
                }
                loop {
                    if chunked_body_complete(&received[head_end..]) {
                        ends.completed.fetch_add(1, Ordering::SeqCst);
                        let _ = socket.write_all(OK_RESPONSE).await;
                        return;
                    }
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            ends.aborted.fetch_add(1, Ordering::SeqCst);
                            return;
                        }
                        Ok(read) => received.extend_from_slice(&buf[..read]),
                    }
                }
            });
        }
    });
    (port, ends, task)
}

/// Wait until the backend has seen one upload close before its terminal chunk.
async fn wait_for_aborted_upload(harness: &GatewayHarness, ends: &StreamedUploadEnds) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while ends.aborted.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the backend must see the streamed upload aborted; completed = {}; logs:\n{}",
            ends.completed.load(Ordering::SeqCst),
            harness.captured_combined().unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The streamed counterpart of the drain test above, over the plain
/// HTTP/3-to-HTTP/1.1 bridge: no retry and no body plugin, so the upload
/// streams to the backend as it arrives. A trailer section ends the body but
/// not the request stream, so the bridge must not end the backend's body until
/// the client's FIN. A client that resets after its trailers, here with
/// `H3_NO_ERROR`, cancelled the request: the backend sees its connection close
/// before the terminal chunk, never a completed upload. The control upload on
/// the same route, trailers then FIN, completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_streamed_upload_aborts_the_backend_body_on_a_reset_after_the_trailer_section() {
    let (backend_port, ends, backend_task) = spawn_streamed_upload_backend(UPLOAD_PATH).await;
    let yaml = gateway_yaml(base_proxy("http", backend_port), Vec::new());
    let (harness, https_port) = spawn_h3_gateway(yaml, &[]).await;
    let url = proxy_url(https_port, UPLOAD_PATH);

    let mut reset = open_upload_stream(&url, "application/octet-stream").await;
    reset
        .send_raw_data(Bytes::from_static(b"cancelled upload"))
        .await
        .expect("send upload");
    reset
        .send_request_trailers(upload_trailers())
        .await
        .expect("send trailers");
    // As in the drain test, the pause lets the gateway read the trailer
    // section before the reset arrives.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        ends.completed.load(Ordering::SeqCst),
        0,
        "a trailer section alone must not end the backend's request body"
    );
    reset.reset_request_upload(h3::error::Code::H3_NO_ERROR);
    wait_for_aborted_upload(&harness, &ends).await;
    assert_eq!(
        ends.completed.load(Ordering::SeqCst),
        0,
        "a request reset after its trailer section must never complete at the backend"
    );
    drop(reset);

    let mut complete = open_upload_stream(&url, "application/octet-stream").await;
    complete
        .send_raw_data(Bytes::from_static(b"complete upload"))
        .await
        .expect("send upload");
    complete
        .send_request_trailers(upload_trailers())
        .await
        .expect("send trailers");
    complete.finish().await.expect("finish upload");
    let (status, _) = complete.recv_response().await.expect("response head");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ends.completed.load(Ordering::SeqCst),
        1,
        "only the upload that ended with FIN completes at the backend"
    );
    assert_eq!(
        ends.aborted.load(Ordering::SeqCst),
        1,
        "the reset upload is the only aborted one"
    );
    backend_task.abort();
}
