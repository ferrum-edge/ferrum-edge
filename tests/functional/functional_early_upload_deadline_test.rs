//! Live H1/H2/H3 coverage for early buffered-upload deadlines (issue #2669 /
//! GHSA-rrx3-m3wf-wg3w).
//!
//! These tests drive real frontend protocol stacks through Ferrum scaffolding
//! (`GatewayHarness` / `TestGateway` + scripted backends + H1/H2/H3 clients).
//! They exercise stalled/trickled early bodies, timeout-`0` + `grpc-timeout`
//! composition, concurrent H3 stream isolation, and multi-consumer prebuffer
//! reuse — not source-text matching.
//!
//! Run:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_early_upload_deadline -- --ignored --nocapture
//! ```

use crate::common::TestGateway;
use crate::scaffolding::backends::{HttpStep, RequestMatcher, ScriptedHttp1Backend};
use crate::scaffolding::clients::{GetOptions, Http2Client, Http3Client, Http3Response};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode};
use serde_json::json;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;

fn early_body_proxy_yaml(backend_port: u16, backend_read_timeout_ms: u64) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "early-upload",
            "listen_path": "/upload",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": backend_read_timeout_ms,
            "backend_write_timeout_ms": 2000,
            "plugins": [
                {"plugin_config_id": "early-ai-guard"},
                {"plugin_config_id": "early-mirror"}
            ],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "early-ai-guard",
                "plugin_name": "ai_request_guard",
                "scope": "proxy",
                "proxy_id": "early-upload",
                "enabled": true,
                "config": {"max_messages": 100},
            },
            {
                "id": "early-mirror",
                "plugin_name": "request_mirror",
                "scope": "proxy",
                "proxy_id": "early-upload",
                "enabled": true,
                "config": {
                    "mirror_host": "127.0.0.1",
                    "mirror_port": 9,
                    "mirror_protocol": "http",
                    "mirror_request_body": true,
                    "percentage": 100,
                },
            }
        ],
    });
    serde_yaml::to_string(&config).expect("yaml")
}

/// Early-body proxy for browser gRPC-Web: grpc_web + cors + request_mirror.
/// `backend_read_timeout_ms = 0` disables the operator whole-upload bound so a
/// short absolute `grpc-timeout` is the sole early-drain ceiling.
fn early_grpc_web_upload_proxy_yaml(backend_port: u16) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "early-grpc-web-upload",
            "listen_path": "/upload",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 0,
            "backend_write_timeout_ms": 2000,
            "plugins": [
                {"plugin_config_id": "early-grpc-web"},
                {"plugin_config_id": "early-cors"},
                {"plugin_config_id": "early-mirror-grpc-web"}
            ],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "early-grpc-web",
                "plugin_name": "grpc_web",
                "scope": "proxy",
                "proxy_id": "early-grpc-web-upload",
                "enabled": true,
                "config": {},
            },
            {
                "id": "early-cors",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "early-grpc-web-upload",
                "enabled": true,
                "config": {"allowed_origins": ["https://app.example"]},
            },
            {
                "id": "early-mirror-grpc-web",
                "plugin_name": "request_mirror",
                "scope": "proxy",
                "proxy_id": "early-grpc-web-upload",
                "enabled": true,
                "config": {
                    "mirror_host": "127.0.0.1",
                    "mirror_port": 9,
                    "mirror_protocol": "http",
                    "mirror_request_body": true,
                    "percentage": 100,
                },
            }
        ],
    });
    serde_yaml::to_string(&config).expect("yaml")
}

fn grpc_web_frames(body: &[u8]) -> Vec<(u8, &[u8])> {
    let mut frames = Vec::new();
    let mut remaining = body;
    while remaining.len() >= 5 {
        let flag = remaining[0];
        let len =
            u32::from_be_bytes([remaining[1], remaining[2], remaining[3], remaining[4]]) as usize;
        if remaining.len() < 5 + len {
            break;
        }
        frames.push((flag, &remaining[5..5 + len]));
        remaining = &remaining[5 + len..];
    }
    frames
}

fn assert_grpc_web_deadline_browser_contract(response: &Http3Response) {
    assert_eq!(
        response.status,
        StatusCode::OK,
        "gRPC-Web deadline rejections ride HTTP 200"
    );
    assert_eq!(
        response
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web"),
        "browser-facing content-type must remain gRPC-Web"
    );
    assert!(
        !response.headers.contains_key("grpc-status")
            && !response.headers.contains_key("grpc-message"),
        "terminal gRPC-Web metadata must remain in the body trailer frame"
    );
    assert_eq!(
        response
            .headers
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://app.example"),
        "deadline rejection must stamp synchronous CORS headers"
    );
    let trailer_payload = grpc_web_frames(response.body_bytes.as_ref())
        .into_iter()
        .find_map(|(flag, payload)| (flag == 0x80).then_some(payload))
        .unwrap_or_else(|| {
            panic!(
                "missing gRPC-Web trailer frame in {:?}",
                response.body_bytes
            )
        });
    let trailer_text = String::from_utf8_lossy(trailer_payload);
    assert!(
        trailer_text.contains("grpc-status: 4\r\n"),
        "expected DEADLINE_EXCEEDED (4) trailer frame, got: {trailer_text}"
    );
}

async fn spawn_ok_backend() -> (u16, ScriptedHttp1Backend) {
    let reservation = reserve_port().await.expect("reserve backend");
    let port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::any()))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "2".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"ok".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn ok backend");
    (port, backend)
}

/// Never-ending body after one JSON prefix chunk — forces the early drain to
/// wait until operator/RPC ceilings fire.
fn stalled_json_body() -> (
    reqwest::Body,
    tokio::task::JoinHandle<()>,
    mpsc::Sender<Result<Bytes, Infallible>>,
) {
    let (tx, rx) = mpsc::channel::<Result<Bytes, Infallible>>(1);
    let body_tx = tx.clone();
    let keeper = tokio::spawn(async move {
        std::future::pending::<()>().await;
        drop(body_tx);
    });
    tx.try_send(Ok(Bytes::from_static(
        br#"{"messages":[{"role":"user","content":"hi"}"#,
    )))
    .expect("seed stalled chunk");
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    (reqwest::Body::wrap_stream(stream), keeper, tx)
}

#[derive(Debug)]
struct DangerAcceptAny;

impl rustls::client::danger::ServerCertVerifier for DangerAcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn h3_post_stalled_body(
    url: &str,
    host: &str,
    addr: SocketAddr,
    content_type: &'static str,
    grpc_timeout: Option<&'static str>,
) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    h3_post_stalled_body_with_origin(url, host, addr, content_type, grpc_timeout, None).await
}

async fn h3_post_stalled_body_with_origin(
    url: &str,
    host: &str,
    addr: SocketAddr,
    content_type: &'static str,
    grpc_timeout: Option<&'static str>,
    origin: Option<&'static str>,
) -> Result<Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    let provider = rustls::crypto::ring::default_provider();
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerAcceptAny))
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
        .map_err(|e| format!("QuicClientConfig: {e}"))?;
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_config)));

    let conn = tokio::time::timeout(Duration::from_secs(10), endpoint.connect(addr, host)?)
        .await
        .map_err(|_| "QUIC handshake timed out")??;
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header(http::header::CONTENT_TYPE, content_type);
    if let Some(timeout) = grpc_timeout {
        req = req.header("grpc-timeout", timeout);
    }
    if let Some(origin) = origin {
        req = req.header(http::header::ORIGIN, origin);
    }
    let req = req.body(())?;
    let mut stream = send_request.send_request(req).await?;
    stream
        .send_data(Bytes::from_static(
            br#"{"messages":[{"role":"user","content":"hi"}"#,
        ))
        .await?;
    // Intentionally do not finish() — stall the early drain.

    let resp = tokio::time::timeout(Duration::from_secs(5), stream.recv_response())
        .await
        .map_err(|_| "recv_response timed out")??;
    let status = resp.status();
    let headers = resp.headers().clone();
    let mut body_bytes = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(2), stream.recv_data()).await {
            Ok(Ok(Some(mut chunk))) => {
                while chunk.has_remaining() {
                    let take = chunk.chunk().to_vec();
                    body_bytes.extend_from_slice(&take);
                    chunk.advance(take.len());
                }
            }
            Ok(Ok(None)) => break,
            Ok(Err(_)) | Err(_) => break,
        }
    }
    drop(send_request);
    driver_task.abort();
    Ok(Http3Response {
        status,
        headers,
        body_bytes: Bytes::from(body_bytes),
        trailers: None,
        body_error: None,
    })
}

async fn spawn_h3_gateway(yaml: String) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();
    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        drop(reservation);

        match TestGateway::builder()
            .mode_file(yaml.clone())
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await
        {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    panic!("failed to spawn H3 gateway: {last_error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_stalled_early_body_hits_operator_whole_upload_timeout() {
    let (backend_port, _backend) = spawn_ok_backend().await;
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(early_body_proxy_yaml(backend_port, 200))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let (body, keeper, _tx) = stalled_json_body();
    let started = Instant::now();
    let resp = harness
        .http_client()
        .expect("client")
        .as_reqwest()
        .post(harness.proxy_url("/upload"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("h1 stalled upload response");
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(
        elapsed < Duration::from_secs(2),
        "operator bound must fire promptly, elapsed={elapsed:?}"
    );
    keeper.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_stalled_early_body_hits_operator_whole_upload_timeout() {
    let (backend_port, _backend) = spawn_ok_backend().await;
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(early_body_proxy_yaml(backend_port, 200))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let client = Http2Client::h2c_prior_knowledge().expect("h2c");
    let (body, keeper, _tx) = stalled_json_body();
    let started = Instant::now();
    let resp = client
        .as_reqwest()
        .post(harness.proxy_url("/upload"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("h2 stalled upload response");
    assert_eq!(resp.version(), reqwest::Version::HTTP_2);
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(
        elapsed < Duration::from_secs(2),
        "operator bound must fire promptly, elapsed={elapsed:?}"
    );
    keeper.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_zero_operator_timeout_still_honors_native_grpc_absolute_deadline() {
    // `backend_read_timeout_ms = 0` disables the operator whole-upload bound,
    // but a native gRPC request's `grpc-timeout` absolute deadline must still
    // cap the request_mirror pre-before_proxy body drain.
    let (backend_port, _backend) = spawn_ok_backend().await;
    let (mut gateway, https_port) = spawn_h3_gateway(early_body_proxy_yaml(backend_port, 0)).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy ready");

    let url = format!("https://127.0.0.1:{https_port}/upload");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port));
    let started = Instant::now();
    let response = h3_post_stalled_body(&url, "localhost", addr, "application/grpc", Some("100m"))
        .await
        .expect("deadline-capped native gRPC H3 upload");
    let elapsed = started.elapsed();
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response
            .headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("4"),
        "native gRPC deadline rejection must be trailers-only DEADLINE_EXCEEDED"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "absolute RPC deadline must fire promptly, elapsed={elapsed:?}"
    );
    gateway.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_stalled_early_grpc_web_upload_honors_absolute_deadline_and_cors() {
    // Stalled early upload with Content-Type: application/grpc-web and a short
    // absolute grpc-timeout. Operator whole-upload bound is disabled so the RPC
    // deadline alone cancels the drain and shapes the browser-facing contract.
    let (backend_port, _backend) = spawn_ok_backend().await;
    let (mut gateway, https_port) =
        spawn_h3_gateway(early_grpc_web_upload_proxy_yaml(backend_port)).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy ready");

    let url = format!("https://127.0.0.1:{https_port}/upload");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port));
    let started = Instant::now();
    let response = h3_post_stalled_body_with_origin(
        &url,
        "localhost",
        addr,
        "application/grpc-web",
        Some("100m"),
        Some("https://app.example"),
    )
    .await
    .expect("deadline-capped gRPC-Web H3 early upload");
    let elapsed = started.elapsed();
    assert_grpc_web_deadline_browser_contract(&response);
    assert!(
        elapsed < Duration::from_secs(2),
        "absolute RPC deadline must fire promptly for gRPC-Web early upload, elapsed={elapsed:?}"
    );
    gateway.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn multiple_early_consumers_share_one_operator_bound_not_stacked_windows() {
    // ai_request_guard + request_mirror both require the early body. They must
    // share one drain / one operator window (~200ms), not stack two fresh
    // windows (~400ms+).
    let (backend_port, _backend) = spawn_ok_backend().await;
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(early_body_proxy_yaml(backend_port, 200))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway");

    let (body, keeper, _tx) = stalled_json_body();
    let started = Instant::now();
    let resp = harness
        .http_client()
        .expect("client")
        .as_reqwest()
        .post(harness.proxy_url("/upload"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("multi-consumer stalled upload");
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(
        elapsed < Duration::from_millis(700),
        "stacked fresh timeouts would approach 400ms+; elapsed={elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(100),
        "operator bound should actually wait; elapsed={elapsed:?}"
    );
    keeper.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_stalled_early_body_hits_operator_whole_upload_timeout() {
    let (backend_port, _backend) = spawn_ok_backend().await;
    let (mut gateway, https_port) =
        spawn_h3_gateway(early_body_proxy_yaml(backend_port, 250)).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy ready");

    let url = format!("https://127.0.0.1:{https_port}/upload");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port));
    let started = Instant::now();
    let mut last_err = None;
    let response = {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match h3_post_stalled_body(&url, "localhost", addr, "application/json", None).await {
                Ok(response) => break response,
                Err(error) if Instant::now() < deadline => {
                    last_err = Some(error.to_string());
                    sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("H3 stalled early upload failed: {error}; prior={last_err:?}"),
            }
        }
    };
    let elapsed = started.elapsed();
    assert_eq!(response.status, StatusCode::REQUEST_TIMEOUT);
    assert!(
        elapsed < Duration::from_secs(3),
        "H3 operator bound must fire promptly, elapsed={elapsed:?}"
    );
    gateway.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_slow_cancelled_stream_does_not_block_independent_sibling_stream() {
    let (backend_port, _backend) = spawn_ok_backend().await;
    let (mut gateway, https_port) =
        spawn_h3_gateway(early_body_proxy_yaml(backend_port, 400)).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy ready");

    let upload_url = format!("https://127.0.0.1:{https_port}/upload");
    let get_url = upload_url.clone();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, https_port));

    let stalled = tokio::spawn(async move {
        h3_post_stalled_body(&upload_url, "localhost", addr, "application/json", None).await
    });

    // Independent GET has no early body phase and should reach the OK backend
    // promptly while the sibling POST is still parked in the early drain.
    sleep(Duration::from_millis(50)).await;
    let client = Http3Client::insecure().expect("h3 client");
    let started = Instant::now();
    let fast = client
        .get_with_options(&get_url, GetOptions::default().method(Method::GET))
        .await
        .expect("independent H3 GET");
    let fast_elapsed = started.elapsed();
    assert_eq!(fast.status, StatusCode::OK);
    assert!(
        fast_elapsed < Duration::from_millis(1500),
        "independent H3 stream blocked by sibling upload; elapsed={fast_elapsed:?}"
    );

    let stalled_response = stalled
        .await
        .expect("join stalled")
        .expect("stalled stream response");
    assert_eq!(stalled_response.status, StatusCode::REQUEST_TIMEOUT);

    gateway.shutdown();
}
