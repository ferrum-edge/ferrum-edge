//! Direct HTTP/1.1 backend pool (issue #5588).
//!
//! HTTP/1.1 backends are dispatched on Ferrum's own exclusive-checkout hyper
//! connection pool instead of reqwest (`FERRUM_POOL_HTTP1_DIRECT`, default on).
//! These tests drive the binary gateway against real HTTP/1.1 backends and
//! check the pool contract: keep-alive reuse, no reuse of a connection the
//! backend closes, a one-shot replay when an idle connection died before the
//! request reached the wire, byte-exact uploads, and the decoder-verified
//! `Content-Length` on streamed responses.
//!
//! Run with: `cargo build --bin ferrum-edge && cargo test --test
//! functional_tests functional_http1_direct_pool -- --ignored --nocapture`

use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use crate::scaffolding::to_file_mode_yaml;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const LARGE_BODY_LEN: usize = 100 * 1024;

fn gateway_yaml(backend_port: u16) -> String {
    to_file_mode_yaml(&json!({
        "version": "1",
        "proxies": [{
            "id": "h1-direct",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    }))
}

/// Keep-alive HTTP/1.1 backend. `/large` returns a fixed-length body bigger
/// than the default response-buffer cutoff (so the gateway streams it), `/echo`
/// returns the request body, anything else returns `hello`.
///
/// Returns the number of TCP connections that carried at least one HTTP/1.1
/// request. Raw accepts are not counted: the gateway's startup backend
/// capability probe opens (and abandons) its own connection.
async fn spawn_keepalive_backend(listener: TcpListener) -> Arc<AtomicU32> {
    let request_conns = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&request_conns);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            let first = Arc::new(AtomicBool::new(true));
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    if first.swap(false, Ordering::SeqCst) {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                    async move {
                        let path = req.uri().path().to_string();
                        let body = match path.as_str() {
                            "/large" => Bytes::from(vec![b'z'; LARGE_BODY_LEN]),
                            "/echo" => req
                                .into_body()
                                .collect()
                                .await
                                .map(|c| c.to_bytes())
                                .unwrap_or_default(),
                            _ => Bytes::from_static(b"hello"),
                        };
                        Ok::<_, Infallible>(Response::new(Full::new(body)))
                    }
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    request_conns
}

/// Read one HTTP/1.1 request head. `None` on EOF, error, or the h2c probe
/// preface the gateway's capability registry sends.
async fn read_request_head(stream: &mut tokio::net::TcpStream) -> Option<()> {
    let mut buf = vec![0u8; 4096];
    let mut seen = Vec::new();
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
    (!seen.starts_with(b"PRI * HTTP/2.0")).then_some(())
}

async fn spawn_gateway(backend_port: u16, direct: bool) -> GatewayHarness {
    GatewayHarness::builder()
        .file_config(gateway_yaml(backend_port))
        .env(
            "FERRUM_POOL_HTTP1_DIRECT",
            if direct { "true" } else { "false" },
        )
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn gateway")
}

async fn assert_reuses_one_backend_connection(direct: bool) {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let request_conns = spawn_keepalive_backend(reservation.into_listener()).await;
    let harness = spawn_gateway(backend_port, direct).await;
    let client = harness.http_client().expect("client");

    for i in 0..5 {
        let resp = client
            .get(&harness.proxy_url("/api/small"))
            .await
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        assert_eq!(resp.status, 200, "request {i}");
        assert_eq!(&resp.body_bytes[..], b"hello", "request {i}");
    }
    let resp = client
        .get(&harness.proxy_url("/api/large"))
        .await
        .expect("large request");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body_bytes.len(), LARGE_BODY_LEN);
    assert_eq!(
        resp.headers
            .get("content-length")
            .and_then(|v| v.to_str().ok()),
        Some(LARGE_BODY_LEN.to_string().as_str()),
        "a streamed HTTP/1.1 backend response must keep its decoder-verified Content-Length"
    );
    assert!(
        resp.headers.get("transfer-encoding").is_none(),
        "the response must not be re-framed as chunked"
    );
    assert_eq!(
        request_conns.load(Ordering::SeqCst),
        1,
        "sequential requests must reuse one keep-alive backend connection (direct={direct})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h1_reuses_one_keepalive_backend_connection() {
    assert_reuses_one_backend_connection(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn reqwest_h1_path_still_serves_when_direct_pool_disabled() {
    assert_reuses_one_backend_connection(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h1_never_reuses_a_connection_the_backend_closes() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let listener = reservation.into_listener();
    let request_conns = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&request_conns);
    // Every response carries `Connection: close` and the socket closes after it.
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                if read_request_head(&mut stream).await.is_none() {
                    return;
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    let harness = spawn_gateway(backend_port, true).await;
    let client = harness.http_client().expect("client");

    for i in 0..3 {
        let resp = client
            .get(&harness.proxy_url("/api/close"))
            .await
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        assert_eq!(resp.status, 200, "request {i}");
        assert_eq!(&resp.body_bytes[..], b"ok", "request {i}");
    }
    assert_eq!(request_conns.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h1_replays_once_when_the_idle_connection_died() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let listener = reservation.into_listener();
    let request_conns = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&request_conns);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                if read_request_head(&mut stream).await.is_none() {
                    return;
                }
                if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                    // Answer as a keep-alive response, then drop the socket:
                    // the gateway pools a connection that is already dead.
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
                        .await;
                    let _ = stream.shutdown().await;
                    return;
                }
                loop {
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nb")
                        .await
                        .is_err()
                        || read_request_head(&mut stream).await.is_none()
                    {
                        return;
                    }
                }
            });
        }
    });
    let harness = spawn_gateway(backend_port, true).await;
    let client = harness.http_client().expect("client");

    let first = client
        .get(&harness.proxy_url("/api/first"))
        .await
        .expect("first request");
    assert_eq!(first.status, 200);
    assert_eq!(&first.body_bytes[..], b"a");
    // Immediately reuse: whether the gateway notices the close before the
    // write (fresh dial) or after (unsent request replayed once), the client
    // must never see the dead connection.
    let second = client
        .get(&harness.proxy_url("/api/second"))
        .await
        .expect("second request");
    assert_eq!(
        second.status, 200,
        "the dead idle connection leaked a failure"
    );
    assert_eq!(&second.body_bytes[..], b"b");
    assert_eq!(request_conns.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h1_streams_uploads_byte_exact() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let request_conns = spawn_keepalive_backend(reservation.into_listener()).await;
    let harness = spawn_gateway(backend_port, true).await;
    let client = harness.http_client().expect("client");

    let payload: Vec<u8> = (0..200 * 1024).map(|i| (i % 251) as u8).collect();
    for i in 0..3 {
        let resp = client
            .request(reqwest::Method::POST, &harness.proxy_url("/api/echo"))
            .body(payload.clone())
            .send()
            .await
            .unwrap_or_else(|e| panic!("upload {i} failed: {e}"));
        assert_eq!(resp.status(), 200, "upload {i}");
        let body = resp.bytes().await.expect("echo body");
        assert_eq!(body.len(), payload.len(), "upload {i}");
        assert!(
            body[..] == payload[..],
            "upload {i} was not forwarded byte-exact"
        );
    }
    assert_eq!(request_conns.load(Ordering::SeqCst), 1);
}
