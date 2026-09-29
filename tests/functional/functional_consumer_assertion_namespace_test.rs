//! The whole `x-consumer-*` request-header namespace is gateway-owned
//! (ferrum-alloy#25 item 4).
//!
//! A client that sends `X-Consumer-Role: admin` / `X-Consumer-Groups: admins`
//! (or a forged `X-Consumer-Username`, or an underscore spelling such as
//! `X_Consumer_Role` that CGI-style backends fold onto the same variable) must
//! not reach any backend, while the gateway-authored `x-consumer-username` /
//! `x-consumer-custom-id` of the authenticated consumer must. Each test
//! authenticates through `key_auth` and asserts on what a scripted backend
//! actually received:
//!
//! - HTTP/1.1, HTTP/2 (h2c), and HTTP/3 frontends to an HTTP/1.1 backend. The
//!   HTTP/3 leg rides the H3-to-HTTP/1.1 cross-protocol bridge.
//! - native gRPC (h2c frontend to an h2c gRPC backend).
//! - HTTP/3 gRPC through the H3-to-HTTP/2 gRPC bridge.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests consumer_assertion_namespace -- --ignored --nocapture
//! ```

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::backends::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, GrpcClient, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const API_KEY: &str = "consumer-namespace-secret-key";
const CONSUMER_USERNAME: &str = "namespace-alice";
const CONSUMER_CUSTOM_ID: &str = "namespace-cust-7";
const FORGED_USERNAME: &str = "forged-namespace-admin";
const APPLICATION_HEADER: &str = "x-app-trace";
const RPC_PATH: &str = "/helloworld.Greeter/SayHello";

/// The hostile client header set every leg sends alongside its credential.
fn hostile_client_headers() -> Vec<(&'static str, String)> {
    vec![
        ("x-api-key", API_KEY.to_string()),
        ("X-Consumer-Role", "admin".to_string()),
        ("X-Consumer-Groups", "admins".to_string()),
        ("X-Consumer-Username", FORGED_USERNAME.to_string()),
        ("X_Consumer_Role", "admin".to_string()),
        ("x_consumer-groups", "admins".to_string()),
        ("x-consumer_username", FORGED_USERNAME.to_string()),
        (APPLICATION_HEADER, "keep-me".to_string()),
    ]
}

/// `key_auth` on `proxy_id` plus the one consumer it authenticates.
fn key_auth_config(proxies: Vec<Value>, proxy_ids: &[&str]) -> String {
    let plugin_configs: Vec<Value> = proxy_ids
        .iter()
        .map(|proxy_id| {
            json!({
                "id": format!("{proxy_id}-key-auth"),
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": proxy_id,
                "enabled": true,
                "config": {}
            })
        })
        .collect();
    let config = json!({
        "version": "1",
        "proxies": proxies,
        "consumers": [{
            "id": "namespace-consumer",
            "username": CONSUMER_USERNAME,
            "custom_id": CONSUMER_CUSTOM_ID,
            "credentials": {"keyauth": [{"key": API_KEY}]}
        }],
        "upstreams": [],
        "plugin_configs": plugin_configs
    });
    serde_yaml::to_string(&config).expect("serialize consumer namespace config")
}

/// Assert one backend-received header list honours the namespace contract.
/// `_` is folded to `-` so an underscore spelling that survived would show up
/// as an unexpected name.
fn assert_backend_consumer_namespace(label: &str, headers: &[(String, String)]) {
    let consumer_headers: Vec<(String, &str)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.as_str()))
        .filter(|(name, _)| name.replace('_', "-").starts_with("x-consumer-"))
        .collect();
    let mut names: Vec<&str> = consumer_headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    let expected_names = ["x-consumer-custom-id", "x-consumer-username"];
    assert_eq!(
        names, expected_names,
        "{label}: only the gateway-authored consumer assertions may reach the backend: \
         {headers:?}"
    );
    for (name, value) in &consumer_headers {
        let expected = if name == "x-consumer-username" {
            CONSUMER_USERNAME
        } else {
            CONSUMER_CUSTOM_ID
        };
        assert_eq!(*value, expected, "{label}: wrong {name}");
    }
    assert!(
        headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(APPLICATION_HEADER) && value == "keep-me"
        }),
        "{label}: an ordinary application header must still reach the backend: {headers:?}"
    );
}

/// Parse the field lines of a raw HTTP/1.1 request head.
fn head_field_lines(head: &str) -> Vec<(String, String)> {
    head.lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// HTTP/1.1, HTTP/2, and HTTP/3 (H3-to-HTTP/1.1 bridge)
// ---------------------------------------------------------------------------

#[ignore]
#[tokio::test]
async fn client_consumer_namespace_never_reaches_http_backends_on_h1_h2_h3() {
    let backend = CapturingBackend::spawn().await;
    let proxy = json!({
        "id": "namespace-http",
        "listen_path": "/",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend.port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": [{"plugin_config_id": "namespace-http-key-auth"}]
    });
    let mut gateway = TestGateway::builder()
        .mode_file(key_auth_config(vec![proxy], &["namespace-http"]))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start consumer namespace gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    // HTTP/1.1
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    let mut request = client.get(gateway.proxy_url("/namespace/h1"));
    for (name, value) in hostile_client_headers() {
        request = request.header(name, value);
    }
    let status = request.send().await.expect("http1 request").status();
    assert_eq!(status, StatusCode::OK, "HTTP/1.1 request failed");

    // HTTP/2 (h2c prior knowledge)
    let stream = TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let uri = format!("http://127.0.0.1:{}/namespace/h2", gateway.proxy_port);
    let mut builder = Request::builder().uri(uri);
    for (name, value) in hostile_client_headers() {
        builder = builder.header(name, value);
    }
    let request = builder.body(Empty::<Bytes>::new()).expect("h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status();
    let _ = response.into_body().collect().await;
    drop(sender);
    conn_task.abort();
    assert_eq!(status, StatusCode::OK, "HTTP/2 request failed");

    // HTTP/3 through the H3-to-HTTP/1.1 cross-protocol bridge
    let h3 = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/namespace/h3");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let status = loop {
        let mut options = GetOptions::default().method(Method::GET);
        for (name, value) in hostile_client_headers() {
            options = options.header(name, value);
        }
        match h3.get_with_options(&url, options).await {
            Ok(response) => break response.status,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 request did not complete: {error}"),
        }
    };
    assert_eq!(status, StatusCode::OK, "HTTP/3 request failed");

    for (label, path) in [
        ("HTTP/1.1", "/namespace/h1"),
        ("HTTP/2", "/namespace/h2"),
        ("HTTP/3 bridge", "/namespace/h3"),
    ] {
        let head = backend
            .wait_for_target_prefix(path, Duration::from_secs(5))
            .await
            .unwrap_or_else(|| panic!("{label}: backend never received {path}"));
        assert!(
            !head.contains(FORGED_USERNAME),
            "{label}: a forged consumer identity reached the backend:\n{head}"
        );
        assert_backend_consumer_namespace(label, &head_field_lines(&head));
    }

    gateway.shutdown();
}

// ---------------------------------------------------------------------------
// Native gRPC (h2c frontend to h2c backend)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn client_consumer_namespace_never_reaches_native_grpc_backends() {
    let reservation = reserve_port().await.expect("reserve grpc backend");
    let backend_port = reservation.port;
    let backend = ScriptedGrpcBackend::builder_plain(reservation.into_listener())
        .step(GrpcStep::AcceptRpc(MatchRpc::method(RPC_PATH)))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "OK",
        })
        .spawn()
        .expect("spawn grpc backend");
    let proxy = json!({
        "id": "namespace-grpc",
        "listen_path": "/namespace-grpc",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "plugins": [{"plugin_config_id": "namespace-grpc-key-auth"}]
    });

    // In-process with warmup off skips the startup capability probe, whose h2c
    // connection would otherwise consume the one-shot backend script.
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(key_auth_config(vec![proxy], &["namespace-grpc"]))
        .log_level("warn")
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");
    let gateway_port: u16 = harness
        .proxy_base_url()
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .expect("gateway http port");
    let client = GrpcClient::h2c(format!("127.0.0.1:{gateway_port}"));

    let response = client
        .unary_with_headers(
            &format!("/namespace-grpc{RPC_PATH}"),
            Bytes::from_static(b"ping"),
            &hostile_client_headers(),
        )
        .await
        .expect("unary rpc");
    assert_eq!(
        response.grpc_status(),
        Some(0),
        "an authenticated RPC must be forwarded; got {response:?}"
    );

    let received = backend.received_streams().await;
    let rpc = received.first().expect("backend received the RPC");
    assert_backend_consumer_namespace("native gRPC", &rpc.headers);
    backend.assert_no_matcher_mismatches().await;
}

// ---------------------------------------------------------------------------
// HTTP/3 gRPC through the H3-to-HTTP/2 gRPC bridge
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn client_consumer_namespace_never_reaches_backends_through_the_h3_grpc_bridge() {
    let backend_listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind grpc backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    let ca = TestCa::new("consumer-namespace-h3-grpc-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let backend = ScriptedGrpcBackend::builder_tls(backend_listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"pong")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn grpc backend");

    let (_harness, https_port) = spawn_h3_grpc_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/namespace-h3-grpc{RPC_PATH}");
    let hostile = hostile_client_headers();
    let refs: Vec<(&str, &str)> = hostile
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut stream = loop {
        match client.open_grpc_stream_with_headers(&url, &refs).await {
            Ok(stream) => break stream,
            Err(error) if std::time::Instant::now() >= deadline => {
                panic!("open_grpc_stream_with_headers never succeeded: {error}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(150)).await,
        }
    };
    stream.send_message(b"ping").await.expect("send message");
    stream.finish().await.expect("finish");
    let (status, _) = stream.recv_response().await.expect("recv response");
    let (_, trailers) = stream
        .recv_body_and_trailers()
        .await
        .expect("recv body+trailers");
    assert_eq!(status.as_u16(), 200, "gRPC rides on HTTP 200");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0"),
        "an authenticated H3 RPC must be forwarded"
    );

    let received = backend.received_streams().await;
    let rpc = received.first().expect("backend received the RPC");
    assert_backend_consumer_namespace("H3-to-gRPC bridge", &rpc.headers);
}

/// Spawn an H3-frontend gateway whose `https` proxy (gRPC is a runtime flavor
/// of it) authenticates with `key_auth` and dials the TLS gRPC backend.
async fn spawn_h3_grpc_gateway(backend_port: u16) -> (GatewayHarness, u16) {
    let proxy = json!({
        "id": "namespace-h3-grpc",
        "listen_path": "/namespace-h3-grpc",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": true,
        "backend_connect_timeout_ms": 2000,
        "backend_read_timeout_ms": 5000,
        "backend_write_timeout_ms": 5000,
        "backend_tls_verify_server_cert": false,
        "plugins": [{"plugin_config_id": "namespace-h3-grpc-key-auth"}]
    });
    let yaml = key_auth_config(vec![proxy], &["namespace-h3-grpc"]);

    // A fixed HTTPS port is released before the subprocess binds it, so retry
    // with a FRESH port and fresh certs rather than the same stolen port.
    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.drop_and_take_port();
        let scratch = tempfile::tempdir().expect("scratch");
        let ca = TestCa::new("consumer-namespace-h3-gw").expect("ca");
        let (cert, key) = ca.valid().expect("frontend leaf");
        let cert_path = scratch.path().join("gw.cert.pem");
        let key_path = scratch.path().join("gw.key.pem");
        std::fs::write(&cert_path, &cert).expect("write cert");
        std::fs::write(&key_path, &key).expect("write key");

        let spawned = GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("info")
            .capture_output()
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env(
                "FERRUM_FRONTEND_TLS_CERT_PATH",
                cert_path.to_string_lossy().into_owned(),
            )
            .env(
                "FERRUM_FRONTEND_TLS_KEY_PATH",
                key_path.to_string_lossy().into_owned(),
            )
            .env("FERRUM_TLS_NO_VERIFY", "true")
            // Warmup off makes the subprocess run its one-shot startup
            // capability probe immediately. That probe only handshakes (TLS +
            // H2, plus a UDP H3 attempt) and opens no stream, so it does not
            // consume the backend's one `AcceptRpc` step; gRPC itself always
            // rides the cross-protocol bridge, never the native-H3 pool.
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match spawned {
            Ok(harness) => {
                // Keep the cert files alive for the gateway's lifetime.
                Box::leak(Box::new(scratch));
                return (harness, https_port);
            }
            Err(error) => last_err = error.to_string(),
        }
    }
    panic!("failed to spawn H3 gRPC gateway after retries: {last_err}");
}

// ---------------------------------------------------------------------------
// Raw HTTP/1.1 capturing backend
// ---------------------------------------------------------------------------

/// Records every request head it receives and answers `200 ok`. Heads are
/// looked up by request-target prefix, so the gateway's startup capability
/// probe (an h2c preface, which also ends in a blank line) cannot shadow the
/// request under test.
struct CapturingBackend {
    port: u16,
    heads: Arc<Mutex<Vec<String>>>,
    notify: Arc<Notify>,
    handle: Option<JoinHandle<()>>,
}

impl CapturingBackend {
    async fn spawn() -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind capture backend");
        let port = listener.local_addr().expect("local addr").port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let heads_task = heads.clone();
        let notify_task = notify.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                let heads = heads_task.clone();
                let notify = notify_task.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    heads.lock().expect("heads lock").push(head);
                    notify.notify_waiters();
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            port,
            heads,
            notify,
            handle: Some(handle),
        }
    }

    fn head_for_target_prefix(&self, prefix: &str) -> Option<String> {
        self.heads
            .lock()
            .expect("heads lock")
            .iter()
            .find(|head| {
                head.lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .is_some_and(|target| target.starts_with(prefix))
            })
            .cloned()
    }

    async fn wait_for_target_prefix(&self, prefix: &str, timeout: Duration) -> Option<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(head) = self.head_for_target_prefix(prefix) {
                return Some(head);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }
}

impl Drop for CapturingBackend {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
