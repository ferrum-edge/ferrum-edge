//! Smoke tests for the scripted-backend scaffolding that don't require the
//! gateway binary — i.e., they exercise the backends + clients directly so
//! `cargo test --test integration_tests` covers the happy paths in under a
//! second.
//!
//! The full failure-mode acceptance suite lives under
//! `tests/functional/scripted_backend_tests.rs` (binary mode, `#[ignore]`).
//! See `tests/scaffolding/mod.rs` for the API docs.

use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, ScriptedTlsBackend,
    TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http1Client;
use crate::scaffolding::ports::reserve_port;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn scripted_tcp_backend_end_to_end() {
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::ReadExact(5))
        .step(TcpStep::Write(b"world".to_vec()))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn");
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    s.write_all(b"hello").await.expect("write");
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.expect("read");
    assert_eq!(resp, b"world");
    assert!(backend.received_contains(b"hello").await);
}

#[tokio::test]
async fn scripted_http1_backend_via_reqwest() {
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "GET", "/ping",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn");

    let url = format!("http://127.0.0.1:{port}/ping");
    let client = Http1Client::insecure().expect("client");
    let resp = client.get(&url).await.expect("get");
    assert_eq!(resp.status, reqwest::StatusCode::OK);
    assert_eq!(resp.body_text(), "pong");
    // The matcher is only informational unless we assert — otherwise a test
    // expecting "GET /ping" would pass for any method/path the client sent.
    backend.assert_no_matcher_mismatches().await;
}

#[tokio::test]
async fn scripted_tls_backend_alpn_negotiation() {
    use rustls_pemfile::certs;
    let ca = TestCa::new("integration-test").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;

    let response_bytes: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(response_bytes))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn");

    // Build a rustls client that advertises h2 first, then http/1.1.
    let mut root = rustls::RootCertStore::empty();
    let mut reader = ca.cert_pem.as_bytes();
    for cert in certs(&mut reader).filter_map(|c| c.ok()) {
        root.add(cert).expect("add ca");
    }
    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(root)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let name =
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("server name");
    let _tls = connector.connect(name, tcp).await.expect("handshake");

    // Wait briefly for the server to record the handshake.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let alpn = backend.last_alpn().await;
    assert_eq!(
        alpn.as_deref(),
        Some(&b"http/1.1"[..]),
        "server picked http/1.1 from h2 → http/1.1 client ALPN offer"
    );
    assert_eq!(backend.handshakes_completed(), 1);
}
