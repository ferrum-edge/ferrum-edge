//! Issue #2442: `response_mock` must not short-circuit native gRPC.
//!
//! The plugin advertises HTTP + WebSocket only. A matching mock rule on a
//! gRPC proxy must leave H2/H3 unary RPCs alone so the backend success or
//! error status/body reach the client — never `grpc-status: 13` with an
//! empty body from reject normalization.
//!
//! Run with:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests response_mock_grpc_exclusion -- --ignored --nocapture
//! ```

use crate::scaffolding::port_registry::TestSocket;

use std::time::Duration;

use crate::scaffolding::backends::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GrpcClient, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use bytes::Bytes;
use serde_json::json;
use tokio::net::TcpListener;

const MOCK_BODY: &str = "mocked-response";
const BACKEND_OK_MSG: &[u8] = b"backend-ok-payload";
const RPC_PATH_SUFFIX: &str = "/helloworld.Greeter/SayHello";

fn h2_file_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "mock-grpc-h2",
            "listen_path": "/grpc",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "plugins": [{ "plugin_config_id": "response-mock" }],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "response-mock",
            "plugin_name": "response_mock",
            "scope": "proxy",
            "proxy_id": "mock-grpc-h2",
            "enabled": true,
            "config": {
                // Default status_code 200 + body would become INTERNAL + empty
                // body if the plugin were still selected for native gRPC.
                "rules": [{
                    "path": RPC_PATH_SUFFIX,
                    "body": MOCK_BODY,
                }],
            },
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn h3_file_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "mock-grpc-h3",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "plugins": [{ "plugin_config_id": "response-mock" }],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "response-mock",
            "plugin_name": "response_mock",
            "scope": "proxy",
            "proxy_id": "mock-grpc-h3",
            "enabled": true,
            "config": {
                "rules": [{
                    "path": RPC_PATH_SUFFIX,
                    "body": MOCK_BODY,
                }],
            },
        }],
    });
    serde_yaml::to_string(&config).expect("serialize yaml")
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("response-mock-grpc-excl").expect("ca");
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

fn gateway_http_port(harness: &GatewayHarness) -> u16 {
    harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .expect("gateway http port")
}

fn grpc_frame(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(message.len() + 5);
    framed.push(0);
    framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
    framed.extend_from_slice(message);
    framed
}

async fn spawn_h3_gateway(backend_port: u16) -> (GatewayHarness, u16) {
    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.drop_and_take_port();

        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());

        match GatewayHarness::builder()
            .file_config(h3_file_config(backend_port))
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(harness) => {
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(e) => last_err = e.to_string(),
        }
    }
    panic!("failed to spawn H3 response_mock exclusion gateway: {last_err}");
}

async fn open_h3_grpc_stream_with_retry(
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_response_mock_excludes_native_grpc_unary_success() {
    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(BACKEND_OK_MSG)))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "OK",
        })
        .spawn()
        .expect("spawn backend");

    let harness = GatewayHarness::builder()
        .file_config(h2_file_config(backend_port))
        .log_level("warn")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(
            &format!("/grpc{RPC_PATH_SUFFIX}"),
            Bytes::from_static(b"ping"),
        )
        .await
        .expect("unary rpc");

    assert_eq!(response.http_status, 200, "gRPC rides on HTTP 200");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "matching response_mock must not rewrite success into INTERNAL; got {response:?}"
    );
    assert_eq!(
        response.messages.as_slice(),
        &[Bytes::from_static(BACKEND_OK_MSG)],
        "backend unary payload must reach the client (mock body must not replace it)"
    );
    let raw = response
        .raw_body_frames
        .iter()
        .flat_map(|f| f.iter().copied())
        .collect::<Vec<_>>();
    assert!(
        !raw.windows(MOCK_BODY.len())
            .any(|w| w == MOCK_BODY.as_bytes()),
        "configured mock body must not appear on the native gRPC wire"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_response_mock_excludes_native_grpc_unary_error() {
    let reservation = reserve_port().await.expect("reserve backend");
    let backend_port = reservation.port;
    let _backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 7,
            message: "permission denied by backend",
        })
        .spawn()
        .expect("spawn backend");

    let harness = GatewayHarness::builder()
        .file_config(h2_file_config(backend_port))
        .log_level("warn")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = GrpcClient::h2c(format!("127.0.0.1:{}", gateway_http_port(&harness)));
    let response = client
        .unary(
            &format!("/grpc{RPC_PATH_SUFFIX}"),
            Bytes::from_static(b"ping"),
        )
        .await
        .expect("unary rpc");

    assert_eq!(response.http_status, 200);
    assert_eq!(
        response.grpc_status(),
        Some(7),
        "backend PERMISSION_DENIED must be forwarded; mock must not turn this into INTERNAL: {response:?}"
    );
    assert!(
        response.messages.is_empty(),
        "trailers-only backend error must not gain a mock payload"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_response_mock_excludes_native_grpc_unary_success() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("response-mock-h3-ok-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(BACKEND_OK_MSG)))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "OK",
        })
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api{RPC_PATH_SUFFIX}");
    let mut stream = open_h3_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, _headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200);
    assert_eq!(
        trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
        Some("0"),
        "H3 native gRPC success must pass through despite response_mock; trailers={trailers:?}"
    );
    assert_eq!(
        body.as_ref(),
        grpc_frame(BACKEND_OK_MSG).as_slice(),
        "backend framed unary payload must reach the H3 client"
    );
    assert!(
        !body
            .windows(MOCK_BODY.len())
            .any(|w| w == MOCK_BODY.as_bytes()),
        "configured mock body must not appear on the H3 gRPC wire"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_response_mock_excludes_native_grpc_unary_error() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    let ca = TestCa::new("response-mock-h3-err-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondStatus {
            code: 5,
            message: "not found by backend",
        })
        .spawn()
        .expect("spawn backend");

    let (_harness, https_port) = spawn_h3_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api{RPC_PATH_SUFFIX}");
    let mut stream = open_h3_grpc_stream_with_retry(&client, &url).await;
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, headers) = stream.recv_response().await.expect("recv response");
    let (body, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");

    assert_eq!(status.as_u16(), 200);
    let grpc_status = trailers
        .get("grpc-status")
        .or_else(|| headers.get("grpc-status"))
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        grpc_status,
        Some("5"),
        "H3 backend NOT_FOUND must be forwarded; mock must not invent INTERNAL: \
         headers={headers:?} trailers={trailers:?}"
    );
    assert!(
        body.is_empty(),
        "trailers-only backend error must not gain a mock payload on H3"
    );
}
