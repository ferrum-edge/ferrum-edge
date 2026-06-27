//! End-to-end tests for the HTTP/3 frontend → non-H3 (H2/h2c) gRPC backend
//! STREAMING-request bridge (`cross_protocol::dispatch_grpc_streaming`).
//!
//! Before this path existed, an H3 gRPC request was fully drained into memory
//! (`drain_h3_body`) before the gateway dialed the backend, so the backend saw
//! no request messages until the client half-closed — breaking true
//! client-streaming / bidirectional RPCs. These tests prove the gateway now
//! forwards request DATA incrementally and, crucially, that a backend can
//! respond BEFORE the H3 client half-closes (the bidi case that previously
//! deadlocked).
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests h3_grpc_streaming -- --ignored --nocapture
//! ```

use std::time::Duration;

use crate::scaffolding::backends::{
    GrpcStep, H2Step, MatchHeaders, MatchRpc, ScriptedGrpcBackend, ScriptedH2Backend,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http3Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use serde_json::json;
use tokio::net::TcpListener;

/// Build a frontend TLS cert + CA PEMs and write them to a scratch dir.
/// Returns `(cert_path, key_path)`.
fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-grpc-stream-gw").expect("ca");
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

/// File-mode YAML for one HTTPS proxy (gRPC is a runtime flavor of `https`)
/// pointing at `(127.0.0.1, backend_port)`.
fn file_mode_yaml(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-grpc-stream",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// Spawn an H3 frontend gateway pointing at `backend_port`. Returns the harness
/// and the HTTPS/QUIC port. `extra_env` lets a test tune e.g. the gRPC recv
/// ceiling. The backend must already be listening on `backend_port`.
async fn spawn_h3_grpc_gateway(
    backend_port: u16,
    extra_env: &[(&str, String)],
) -> (GatewayHarness, u16) {
    // Outer retry (codex P3): `FERRUM_PROXY_HTTPS_PORT` is a fixed port we
    // reserve-then-drop before the subprocess binds it, so a parallel test can
    // steal it in the bind-drop-rebind window. Re-reserve a FRESH port (and fresh
    // certs) and re-spawn on failure rather than retrying the same stolen port —
    // per the testing.md "port allocation must retry" rule.
    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());

        let mut builder = GatewayHarness::builder()
            .file_config(file_mode_yaml(backend_port))
            .log_level("info")
            .capture_output()
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            // gRPC always uses the cross-protocol bridge (never the native-H3 pool),
            // so the capability registry is irrelevant — skip the warmup probe.
            .env("FERRUM_POOL_WARMUP_ENABLED", "false");
        for (k, v) in extra_env {
            builder = builder.env(*k, v.clone());
        }
        match builder.spawn().await {
            Ok(harness) => {
                // Keep the cert files alive for the gateway's lifetime.
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("failed to spawn H3 gRPC gateway after retries: {last_err}");
}

/// Length-prefix a gRPC message (1-byte flag + 4-byte BE length + payload).
fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

/// Open an H3 gRPC stream, retrying the QUIC handshake briefly so the test does
/// not race the gateway's listener coming up.
async fn open_grpc_stream_with_retry(
    client: &Http3Client,
    url: &str,
) -> crate::scaffolding::clients::Http3GrpcStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match client.open_grpc_stream(url).await {
            Ok(stream) => return stream,
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    panic!("open_grpc_stream never succeeded: {e}");
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// 1. Regression: unary H3 → H2 gRPC still succeeds through the streaming path,
//    including grpc-status / grpc-message trailers.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_unary_roundtrip() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-unary-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, _headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200, "gRPC rides on HTTP 200");
    assert_eq!(
        body.as_ref(),
        grpc_frame(b"pong").as_slice(),
        "backend response message must reach the H3 client intact"
    );
    assert_eq!(
        trailers.get("grpc-status").map(|v| v.to_str().unwrap()),
        Some("0"),
        "grpc-status trailer must be preserved through the streaming bridge"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// 2. THE KILLER TEST — bidi: the backend responds BEFORE the H3 client
//    half-closes. The backend never drains the request body; it replies on
//    request HEADERS alone. With the old buffered path the gateway waited for
//    the client's END_STREAM before dialing the backend, so this deadlocked
//    (recv_response timed out). The streaming path forwards request headers
//    immediately, so the response arrives while the request stream is still
//    open.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_server_responds_before_client_half_close() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-bidi-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    // Raw H2 script: respond on request HEADERS without ever draining the
    // request body — i.e. before the client half-closes.
    let _backend = ScriptedH2Backend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(H2Step::ExpectHeaders(MatchHeaders::any()))
        .step(H2Step::RespondHeaders(vec![
            (":status", "200".into()),
            ("content-type", "application/grpc".into()),
        ]))
        .step(H2Step::RespondData {
            data: Bytes::from(grpc_frame(b"early-reply")),
            end_stream: false,
        })
        .step(H2Step::RespondTrailers(vec![("grpc-status", "0".into())]))
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port, &[]).await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Bidi");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;

    // Send the first request message but DO NOT finish — leave the request
    // stream open, exactly like a bidi client awaiting the server's reply.
    stream.send_message(b"hello").await.expect("send message");

    // The whole exchange must complete well within the test budget; on the old
    // buffered path this block hangs until the per-call timeout fires.
    let (status, body, trailers) = tokio::time::timeout(Duration::from_secs(10), async {
        let (status, _headers) = stream.recv_response().await.expect("recv response");
        let (body, trailers) = stream
            .recv_body_and_trailers()
            .await
            .expect("recv body+trailers");
        (status, body, trailers)
    })
    .await
    .expect("backend must respond BEFORE the client half-closes (streaming bridge)");

    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        body.as_ref(),
        grpc_frame(b"early-reply").as_slice(),
        "server-streamed message must reach the client before half-close"
    );
    assert_eq!(
        trailers.get("grpc-status").map(|v| v.to_str().unwrap()),
        Some("0"),
    );

    // The proof above is decisive: the full response (headers + message +
    // grpc-status trailer) arrived while the request stream was still open, which
    // is impossible on the old buffered path. The client now half-closes
    // best-effort — once the RPC completes the gateway STOP_SENDINGs the request
    // upload (the RPC is over; no more request DATA is wanted), so a late
    // `finish()` may legitimately observe the already-closed stream.
    let _ = stream.finish().await;
}

// ────────────────────────────────────────────────────────────────────────────
// 3. The max gRPC request size is enforced INCREMENTALLY while streaming (the
//    H3 client sends no Content-Length, so the size ceiling is checked frame by
//    frame in `GrpcBody::Channel`, not via the header fast path). An oversized
//    upload must surface as gRPC RESOURCE_EXHAUSTED (status 8), not a transport
//    error.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_grpc_streaming_enforces_max_request_size_incrementally() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("h3-grpc-size-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    // The backend would happily reply, but the gateway must reject the oversized
    // upload mid-stream before the RPC can complete.
    let _backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"unexpected")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    // 32-byte gRPC recv ceiling; the framed message below is far larger.
    let (_harness, https_port) = spawn_h3_grpc_gateway(
        backend_port,
        &[("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "32".into())],
    )
    .await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Big");
    let mut stream = open_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(&vec![b'x'; 4096]).await.expect("send");
    stream.finish().await.expect("finish");

    let (status, headers) = stream.recv_response().await.expect("recv response");
    // The gateway emits a trailers-only gRPC error: HTTP 200 + grpc-status in the
    // header block (8 = RESOURCE_EXHAUSTED). Drain any body to a clean close.
    let _ = stream.recv_body_and_trailers().await;
    assert_eq!(status.as_u16(), 200, "gRPC errors ride on HTTP 200");
    assert_eq!(
        headers.get("grpc-status").map(|v| v.to_str().unwrap()),
        Some("8"),
        "oversized streaming upload must map to RESOURCE_EXHAUSTED (8)"
    );
}
