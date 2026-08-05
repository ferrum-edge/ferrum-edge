//! Functional coverage for HTTP/3 request-body proxying.
//!
//! Run: `cargo test --test functional_tests functional_h3_request_body -- --ignored --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::clients::bind_quinn_client_endpoint;

use bytes::{Buf, Bytes};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response};
use hyper_util::rt::TokioIo;
use quinn::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

const BODY_BYTES: usize = 10 * 1024 * 1024 + 1024;

fn build_config(backend_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"h3-request-body\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         \x20   backend_connect_timeout_ms: 60000\n\
         \x20   backend_read_timeout_ms: 60000\n\
         \x20   backend_write_timeout_ms: 60000\n\
         consumers: []\n\
         plugin_configs: []\n",
    )
}

fn build_config_with_stdout_logging(backend_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"h3-request-body\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         \x20   backend_connect_timeout_ms: 60000\n\
         \x20   backend_read_timeout_ms: 60000\n\
         \x20   backend_write_timeout_ms: 60000\n\
         consumers: []\n\
         plugin_configs:\n\
         \x20 - id: \"access-log\"\n\
         \x20   plugin_name: \"stdout_logging\"\n\
         \x20   scope: \"global\"\n\
         \x20   enabled: true\n\
         \x20   config: {{}}\n",
    )
}

fn build_serverless_redirect_config(backend_port: u16, function_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"h3-serverless-policy\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         \x20   plugins:\n\
         \x20     - plugin_config_id: \"h3-serverless\"\n\
         consumers: []\n\
         plugin_configs:\n\
         \x20 - id: \"h3-serverless\"\n\
         \x20   plugin_name: \"serverless_function\"\n\
         \x20   scope: \"proxy\"\n\
         \x20   proxy_id: \"h3-serverless-policy\"\n\
         \x20   enabled: true\n\
         \x20   config:\n\
         \x20     provider: \"azure_functions\"\n\
         \x20     function_url: \"http://127.0.0.1:{function_port}/policy\"\n\
         \x20     mode: \"pre_proxy\"\n\
         \x20     forward_query_params: true\n\
         \x20     on_error: \"reject\"\n\
         \x20     error_status_code: 403\n",
    )
}

async fn wait_for_access_log_bytes_sent(gateway: &TestGateway, expected: u64) -> Option<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let latest = gateway.read_combined_captured_output().unwrap_or_default();
        if let Some(entry) = latest
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|entry| {
                entry.get("proxy_id").and_then(Value::as_str) == Some("h3-request-body")
                    && entry.get("bytes_sent").and_then(Value::as_u64) == Some(expected)
            })
        {
            return Some(entry);
        }
        if Instant::now() >= deadline {
            return latest
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .find(|entry| {
                    entry.get("proxy_id").and_then(Value::as_str) == Some("h3-request-body")
                });
        }
        sleep(Duration::from_millis(100)).await;
    }
}

/// Spawn an H3-enabled file-mode gateway with a freshly reserved HTTPS port.
///
/// `FERRUM_PROXY_HTTPS_PORT` is pinned for one inner `TestGateway` spawn. The
/// harness's ordinary retry loop can replace proxy/admin ports, but it cannot
/// change this env-pinned TCP+UDP port after another parallel process steals
/// it between reservation release and gateway bind. Own retries at this outer
/// layer with a fresh reservation and `max_attempts(1)` so a stolen port is
/// never retried; keep using the authenticated ownership barrier.
async fn spawn_h3_request_body_gateway(
    file_config: String,
    extra_env: &[(&str, &str)],
) -> (TestGateway, u16) {
    const OUTER_MAX_ATTEMPTS: u32 = 5;
    let mut last_error = None;

    for attempt in 1..=OUTER_MAX_ATTEMPTS {
        let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let https_port = https_reservation.local_addr().unwrap().port();
        drop(https_reservation);

        let mut builder = TestGateway::builder()
            .mode_file(file_config.clone())
            .log_level("warn")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key");
        for (key, value) in extra_env {
            builder = builder.env(*key, (*value).to_string());
        }

        match builder.spawn().await {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                eprintln!(
                    "spawn_h3_request_body_gateway attempt {attempt}/{OUTER_MAX_ATTEMPTS} \
                     failed (https_port={https_port}): {error}"
                );
                last_error = Some(error.to_string());
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!(
        "spawn_h3_request_body_gateway exhausted {OUTER_MAX_ATTEMPTS} fresh HTTPS ports; \
         last error: {}",
        last_error.as_deref().unwrap_or("no recorded error")
    );
}

async fn start_body_count_backend(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let service = service_fn(|req: HyperRequest<Incoming>| async move {
                let body = req
                    .into_body()
                    .collect()
                    .await
                    .map(|collected| collected.to_bytes())
                    .unwrap_or_default();
                let response_body = format!(r#"{{"received_body_bytes":{}}}"#, body.len());
                let response = Response::builder()
                    .status(200)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(response_body)))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                Ok::<_, Infallible>(response)
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn start_redirect_function(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let service = service_fn(|_req: HyperRequest<Incoming>| async move {
                let response = Response::builder()
                    .status(302)
                    .header(http::header::LOCATION, "/moved")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())));
                Ok::<_, Infallible>(response)
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn h3_post_bytes(
    url: &str,
    body: Bytes,
) -> Result<(StatusCode, Bytes), Box<dyn std::error::Error + Send + Sync>> {
    let parsed: http::Uri = url.parse()?;
    let host = parsed.host().ok_or("missing host in url")?.to_string();
    let port = parsed.port_u16().unwrap_or(443);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    let provider = rustls::crypto::ring::default_provider();
    let verifier = Arc::new(DangerousAcceptAnyServer);
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
        .map_err(|e| format!("QuicClientConfig build failed: {e}"))?;
    let client_config = ClientConfig::new(Arc::new(quic_config));
    let mut endpoint = bind_quinn_client_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    endpoint.set_default_client_config(client_config);

    let conn = tokio::time::timeout(Duration::from_secs(15), endpoint.connect(addr, &host)?)
        .await
        .map_err(|_| "QUIC handshake timed out")??;
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| format!("h3 new: {e}"))?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = Request::builder()
        .method(http::Method::POST)
        .uri(url)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())
        .map_err(|e| format!("build request: {e}"))?;
    let mut stream = tokio::time::timeout(Duration::from_secs(15), send_request.send_request(req))
        .await
        .map_err(|_| "send_request timed out")?
        .map_err(|e| format!("send_request: {e}"))?;

    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + 16 * 1024).min(body.len());
        let chunk = body.slice(offset..end);
        tokio::time::timeout(Duration::from_secs(60), stream.send_data(chunk))
            .await
            .map_err(|_| "send_data timed out")?
            .map_err(|e| format!("send_data: {e}"))?;
        offset = end;
    }
    stream
        .finish()
        .await
        .map_err(|e| format!("finish request body: {e}"))?;

    let resp = tokio::time::timeout(Duration::from_secs(60), stream.recv_response())
        .await
        .map_err(|_| "recv_response timed out")?
        .map_err(|e| format!("recv_response: {e}"))?;
    let status = resp.status();
    let mut body_bytes = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(15), stream.recv_data()).await {
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

    let _ = stream.recv_trailers().await;
    drop(send_request);
    driver_task.abort();
    Ok((status, Bytes::from(body_bytes)))
}

#[ignore]
#[tokio::test]
async fn functional_h3_request_body_zero_limit_forwards_large_post() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_body_count_backend(backend_listener));
    sleep(Duration::from_millis(150)).await;

    let (mut gateway, https_port) = spawn_h3_request_body_gateway(
        build_config(backend_port),
        &[("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")],
    )
    .await;

    let url = format!("https://localhost:{https_port}/upload");
    let body = Bytes::from(vec![b'a'; BODY_BYTES]);
    let mut last_err = None;
    let (status, body_bytes) = {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match h3_post_bytes(&url, body.clone()).await {
                Ok(response) => break response,
                Err(err) if Instant::now() < deadline => {
                    last_err = Some(err.to_string());
                    sleep(Duration::from_millis(100)).await;
                }
                Err(err) => {
                    let logs = gateway.read_combined_captured_output().unwrap_or_default();
                    panic!(
                        "H3 POST did not complete with request body limit disabled; last error={last_err:?}; final error={err}\n--- gateway logs ---\n{logs}"
                    );
                }
            }
        }
    };

    assert_eq!(
        status.as_u16(),
        200,
        "body={}",
        String::from_utf8_lossy(&body_bytes)
    );
    let parsed: Value = serde_json::from_slice(&body_bytes).expect("json response");
    assert_eq!(
        parsed["received_body_bytes"].as_u64(),
        Some(BODY_BYTES as u64),
        "backend should receive the full H3 request body when request limit is disabled"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_h3_serverless_redirect_is_not_pre_proxy_approval() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_body_count_backend(backend_listener));
    let function_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let function_port = function_listener.local_addr().unwrap().port();
    let function_task = tokio::spawn(start_redirect_function(function_listener));
    sleep(Duration::from_millis(150)).await;

    let (mut gateway, https_port) = spawn_h3_request_body_gateway(
        build_serverless_redirect_config(backend_port, function_port),
        &[],
    )
    .await;

    let url = format!("https://localhost:{https_port}/protected?name=alice%20bob");
    let (status, body) = h3_post_bytes(&url, Bytes::new())
        .await
        .unwrap_or_else(|error| {
            let logs = gateway.read_combined_captured_output().unwrap_or_default();
            panic!("H3 serverless request failed: {error}; logs={logs}")
        });
    assert_eq!(status.as_u16(), 403);
    assert!(String::from_utf8_lossy(&body).contains("function_non_success_status"));

    gateway.shutdown();
    backend_task.abort();
    function_task.abort();
}

/// Coverage scope (read before assuming this guards the native H3 byte
/// plumbing): this test uses `backend_scheme: http`, which normalizes to
/// `DispatchKind::HttpPool`, so an H3 frontend request takes the
/// **cross-protocol bridge** to an HTTP/1.1 backend. On that path `bytes_sent`
/// is sourced from the bridge's own counter (`http3/cross_protocol.rs`), so
/// this exercises the bridge's request-byte accounting end to end.
///
/// It does NOT exercise the **native H3 backend pool** path — the
/// `request_body_bytes_seen` / `bytes_seen.fetch_add(...)` plumbing in
/// `http3/client.rs::do_request_streaming_body` and the native streaming block
/// in `http3/server.rs`. That path runs only for `DispatchKind::HttpsPool`
/// against an H3-capable backend (`backend_scheme: https` +
/// `FERRUM_POOL_WARMUP_ENABLED=true` so the capability registry marks H3
/// `Supported`). Adding native-pool byte-count coverage requires a scripted
/// QUIC/H3 backend that consumes the request body and responds — see the
/// `tests/functional/scripted_backend_h3_tests.rs` harness
/// (`spawn_h3_harness_with_explicit_https_port`, `wait_for_capability_entry`)
/// — and is tracked as a follow-up; it needs a body-consuming `ScriptedH3Backend`
/// step the current capability-probe harness does not yet provide.
#[ignore]
#[tokio::test]
async fn functional_h3_streaming_request_logs_request_body_bytes_via_cross_protocol_bridge() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(start_body_count_backend(backend_listener));
    sleep(Duration::from_millis(150)).await;

    let (mut gateway, https_port) = spawn_h3_request_body_gateway(
        build_config_with_stdout_logging(backend_port),
        &[("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")],
    )
    .await;

    let url = format!("https://localhost:{https_port}/upload");
    let body = Bytes::from(vec![b'b'; 128 * 1024]);
    let (status, body_bytes) = h3_post_bytes(&url, body.clone()).await.expect("h3 post");

    assert_eq!(status.as_u16(), 200);
    let parsed: Value = serde_json::from_slice(&body_bytes).expect("json response");
    assert_eq!(
        parsed["received_body_bytes"].as_u64(),
        Some(body.len() as u64)
    );

    let access_log = wait_for_access_log_bytes_sent(&gateway, body.len() as u64)
        .await
        .unwrap_or_else(|| {
            let logs = gateway.read_combined_captured_output().unwrap_or_default();
            panic!("stdout_logging did not emit h3 access log; captured logs:\n{logs}")
        });
    assert_eq!(
        access_log.get("bytes_sent").and_then(Value::as_u64),
        Some(body.len() as u64),
        "access log should report the streamed H3 request body bytes"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[derive(Debug)]
struct DangerousAcceptAnyServer;

impl rustls::client::danger::ServerCertVerifier for DangerousAcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}
