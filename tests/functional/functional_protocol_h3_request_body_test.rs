//! Functional coverage for HTTP/3 request-body proxying.
//!
//! Run: `cargo test --test functional_tests functional_h3_request_body -- --ignored --nocapture`

use crate::common::TestGateway;

use bytes::{Buf, Bytes};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request as HyperRequest, Response};
use hyper_util::rt::TokioIo;
use quinn::{ClientConfig, Endpoint};
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
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
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

    let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_reservation.local_addr().unwrap().port();
    drop(https_reservation);

    let mut gateway = TestGateway::builder()
        .mode_file(build_config(backend_port))
        .log_level("warn")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .spawn()
        .await
        .expect("start gateway");

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
