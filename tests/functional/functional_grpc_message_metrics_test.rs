//! Live regression for authoritative gRPC REQUEST/RESPONSE message metrics.
//!
//! Proves H2 and native H3 frontends populate
//! `ferrum_mesh_request_messages_total` / `ferrum_mesh_response_messages_total`
//! from length-prefixed framing observed on the live body adapters — not from
//! manually seeded summaries.
//!
//! Also covers translated gRPC-Web: the counters must describe the NATIVE gRPC
//! representation exchanged with the backend, so a text-mode client whose wire
//! body is base64 (and whose response is re-armoured on the way out) still
//! reports the true message counts rather than zero.
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests grpc_message_metrics -- --ignored --nocapture
//! ```

use crate::scaffolding::backends::{GrpcStep, MatchRpc, ScriptedGrpcBackend};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http3Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http_body_util::Full;
use hyper::Request;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::sleep;

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn metric_line_value(metrics: &str, series_prefix: &str) -> Option<u64> {
    metrics.lines().find_map(|line| {
        if !line.starts_with(series_prefix) {
            return None;
        }
        line.rsplit_once(' ')
            .and_then(|(_, value)| value.parse::<u64>().ok())
    })
}

async fn wait_for_message_metrics(
    gateway: &GatewayHarness,
    expected_requests: u64,
    expected_responses: u64,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let metrics = gateway.metrics().await.expect("scrape metrics");
        let requests = metric_line_value(&metrics, "ferrum_mesh_request_messages_total{");
        let responses = metric_line_value(&metrics, "ferrum_mesh_response_messages_total{");
        if requests == Some(expected_requests) && responses == Some(expected_responses) {
            return metrics;
        }
        if std::time::Instant::now() >= deadline {
            return metrics;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn mesh_metric_plugins() -> serde_json::Value {
    json!([
        {
            "id": "prom",
            "plugin_name": "prometheus_metrics",
            "scope": "global",
            "enabled": true,
            "config": { "render_cache_ttl_seconds": 0 }
        },
        {
            "id": "workload-metrics",
            "plugin_name": "workload_metrics",
            "scope": "global",
            "enabled": true,
            "config": {
                "namespace": "default",
                "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
                "labels": { "app": "frontend" }
            }
        }
    ])
}

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("grpc-msg-metrics-gw").expect("ca");
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

async fn send_h2_grpc_two_messages(
    gateway_addr: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut body = grpc_frame(b"one");
    body.extend_from_slice(&grpc_frame(b"two"));
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(body)))?;
    let response = sender.send_request(req).await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    let (_parts, body) = response.into_parts();
    use http_body_util::BodyExt;
    let _ = body.collect().await?;
    Ok(())
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_grpc_message_metrics_are_nonzero_and_exact() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = listener.local_addr().unwrap().port();
    let _backend = ScriptedGrpcBackend::builder_plain(listener)
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"a")))
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"b")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-msg-metrics",
            "listen_path": "/grpc",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true
        }],
        "consumers": [],
        "plugin_configs": mesh_metric_plugins(),
    });
    let yaml = serde_yaml::to_string(&config).expect("yaml");
    let gateway = GatewayHarness::builder()
        .file_config(yaml)
        .env("FERRUM_ACCEPT_THREADS", "1")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("spawn gateway");

    let proxy_host = gateway
        .proxy_base_url()
        .trim_start_matches("http://")
        .to_string();
    send_h2_grpc_two_messages(&proxy_host, "/grpc/my.Echo/Echo")
        .await
        .expect("h2 grpc");

    let metrics = wait_for_message_metrics(&gateway, 2, 2).await;
    let req = metric_line_value(&metrics, "ferrum_mesh_request_messages_total{")
        .expect("request message series missing");
    let resp = metric_line_value(&metrics, "ferrum_mesh_response_messages_total{")
        .expect("response message series missing");
    assert_eq!(req, 2, "H2 gRPC request messages:\n{metrics}");
    assert_eq!(resp, 2, "H2 gRPC response messages:\n{metrics}");
}

/// Proxy config for a browser gRPC-Web client in front of a native gRPC
/// backend: the `grpc_web` plugin owns request decode / response re-framing.
fn grpc_web_metrics_config(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "grpc-web-msg-metrics",
            "listen_path": "/grpc",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": [{"plugin_config_id": "grpc-web"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "grpc-web",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "grpc-web-msg-metrics",
                "enabled": true,
                "config": {},
            },
            {
                "id": "prom",
                "plugin_name": "prometheus_metrics",
                "scope": "global",
                "enabled": true,
                "config": { "render_cache_ttl_seconds": 0 }
            },
            {
                "id": "workload-metrics",
                "plugin_name": "workload_metrics",
                "scope": "global",
                "enabled": true,
                "config": {
                    "namespace": "default",
                    "workload_spiffe_id": "spiffe://cluster.local/ns/default/sa/frontend",
                    "labels": { "app": "frontend" }
                }
            }
        ],
    });
    serde_yaml::to_string(&config).expect("yaml")
}

async fn send_h2_grpc_web(
    gateway_addr: &str,
    path: &str,
    content_type: &str,
    body: Vec<u8>,
) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
    use http_body_util::BodyExt;

    let addr: SocketAddr = gateway_addr.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))?;
    let response = sender.send_request(req).await?;
    assert_eq!(response.status(), http::StatusCode::OK);
    Ok(response.into_body().collect().await?.to_bytes())
}

/// Two-message gRPC-Web request/response over the real H1/H2 translation path.
///
/// Binary mode is the parity control (client wire == native framing); text mode
/// is the regression: its wire body is base64, so counting the client-visible
/// representation reports zero messages in both directions.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_web_message_metrics_count_native_frames_not_client_wire() {
    const REQUEST_SERIES: &str = "ferrum_mesh_request_messages_total{";
    const RESPONSE_SERIES: &str = "ferrum_mesh_response_messages_total{";

    for (label, content_type, text_mode) in [
        ("binary", "application/grpc-web+proto", false),
        ("text", "application/grpc-web-text+proto", true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = listener.local_addr().unwrap().port();
        let _backend = ScriptedGrpcBackend::builder_plain(listener)
            .step(GrpcStep::AcceptRpc(MatchRpc::any()))
            .step(GrpcStep::SendInitialHeaders)
            .step(GrpcStep::RespondMessage(Bytes::from_static(b"a")))
            .step(GrpcStep::RespondMessage(Bytes::from_static(b"b")))
            .step(GrpcStep::RespondStatus {
                code: 0,
                message: "",
            })
            .spawn()
            .expect("spawn backend");

        let gateway = GatewayHarness::builder()
            .file_config(grpc_web_metrics_config(backend_port))
            .env("FERRUM_ACCEPT_THREADS", "1")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
            .expect("spawn gateway");

        let mut native = grpc_frame(b"one");
        native.extend_from_slice(&grpc_frame(b"two"));
        let wire = if text_mode {
            BASE64.encode(&native).into_bytes()
        } else {
            native
        };

        let proxy_host = gateway
            .proxy_base_url()
            .trim_start_matches("http://")
            .to_string();
        let path = "/grpc/my.Echo/Echo";
        let client_body = send_h2_grpc_web(&proxy_host, path, content_type, wire)
            .await
            .unwrap_or_else(|e| panic!("{label} gRPC-Web request: {e}"));

        if text_mode {
            // The client-visible response is base64-armoured, so scanning it as
            // gRPC framing is exactly the mistake this test guards against.
            assert!(
                BASE64.decode(&client_body[..]).is_ok(),
                "{label}: response body must be base64 text mode"
            );
        }

        let metrics = wait_for_message_metrics(&gateway, 2, 2).await;
        let requests = metric_line_value(&metrics, REQUEST_SERIES);
        let responses = metric_line_value(&metrics, RESPONSE_SERIES);
        assert_eq!(
            requests,
            Some(2),
            "{label} gRPC-Web request messages must count the decoded native body:\n{metrics}"
        );
        assert_eq!(
            responses,
            Some(2),
            "{label} gRPC-Web response messages must count the backend frames:\n{metrics}"
        );
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h3_grpc_message_metrics_are_nonzero_and_exact() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend");
    let backend_port = listener.local_addr().unwrap().port();
    let ca = TestCa::new("grpc-msg-h3-be").expect("ca");
    let (be_cert, be_key) = ca.valid().expect("backend leaf");
    let _backend = ScriptedGrpcBackend::builder_tls(listener, &be_cert, &be_key)
        .expect("backend tls")
        .step(GrpcStep::AcceptRpc(MatchRpc::any()))
        .step(GrpcStep::SendInitialHeaders)
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"a")))
        .step(GrpcStep::RespondMessage(Bytes::from_static(b"b")))
        .step(GrpcStep::RespondStatus {
            code: 0,
            message: "",
        })
        .spawn()
        .expect("spawn backend");

    let mut last_err = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.drop_and_take_port();
        let scratch = tempfile::tempdir().expect("scratch");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        let config = json!({
            "version": "1",
            "proxies": [{
                "id": "h3-grpc-msg-metrics",
                "listen_path": "/api",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "backend_tls_verify_server_cert": false,
                "backend_connect_timeout_ms": 2000,
                "backend_read_timeout_ms": 5000,
            }],
            "consumers": [],
            "plugin_configs": mesh_metric_plugins(),
        });
        let yaml = serde_yaml::to_string(&config).expect("yaml");
        let gateway = match GatewayHarness::builder()
            .file_config(yaml)
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .env("FERRUM_ACCEPT_THREADS", "1")
            .env("FERRUM_POOL_WARMUP_ENABLED", "true")
            .spawn()
            .await
        {
            Ok(g) => g,
            Err(e) => {
                last_err = e.to_string();
                continue;
            }
        };

        let client = Http3Client::insecure().expect("h3 client");
        let url = format!("https://127.0.0.1:{https_port}/api/echo.Echo/Unary");
        let mut stream = {
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            loop {
                match client.open_grpc_stream(&url).await {
                    Ok(s) => break s,
                    Err(e) => {
                        if std::time::Instant::now() >= deadline {
                            panic!("open_grpc_stream never succeeded: {e}");
                        }
                        tokio::time::sleep(Duration::from_millis(150)).await;
                    }
                }
            }
        };
        stream.send_message(b"one").await.expect("send one");
        stream.send_message(b"two").await.expect("send two");
        stream.finish().await.expect("finish");
        let (status, _headers) = stream.recv_response().await.expect("headers");
        assert_eq!(status.as_u16(), 200);
        let (_body, trailers) = stream
            .recv_body_and_trailers()
            .await
            .expect("body+trailers");
        assert_eq!(
            trailers.get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("0")
        );

        let metrics = wait_for_message_metrics(&gateway, 2, 2).await;
        let req = metric_line_value(&metrics, "ferrum_mesh_request_messages_total{")
            .expect("H3 request message series missing");
        let resp = metric_line_value(&metrics, "ferrum_mesh_response_messages_total{")
            .expect("H3 response message series missing");
        assert_eq!(req, 2, "H3 gRPC request messages:\n{metrics}");
        assert_eq!(resp, 2, "H3 gRPC response messages:\n{metrics}");
        return;
    }
    panic!("failed to spawn H3 gateway after retries: {last_err}");
}
