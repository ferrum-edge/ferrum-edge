//! Direct HTTP/1.1 backend pool (issue #5588).
//!
//! HTTP/1.1 backends are dispatched on Ferrum's own exclusive-checkout hyper
//! connection pool instead of reqwest (`FERRUM_POOL_HTTP1_DIRECT`, default on).
//! These tests drive the binary gateway against real HTTP/1.1 backends and
//! check the pool contract: keep-alive reuse, no reuse of a connection the
//! backend closes, a one-shot replay when an idle connection died before the
//! request reached the wire, byte-exact uploads, and the decoder-verified
//! `Content-Length` on streamed responses. They also check that an HTTP/2
//! client's masked reset reaches the backend as an aborted upload on both the
//! direct pool and the reqwest path (issue #6022).
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
        .log_level("debug")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway")
}

/// Logged once per dial by the direct HTTP/1.1 pool only, so a test can prove
/// which transport served it (the reqwest path never logs it).
const DIRECT_H1_DIAL_MARKER: &str = "direct HTTP/1.1 pool dialed a backend connection";

async fn assert_transport(harness: &GatewayHarness, direct: bool) {
    let logs = if direct {
        harness
            .wait_for_log_contains(
                |logs| logs.contains(DIRECT_H1_DIAL_MARKER),
                std::time::Duration::from_secs(5),
            )
            .await
    } else {
        // Give the log writer time to flush, so capture lag cannot hide a
        // marker the reqwest path should never have logged.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        harness.captured_combined().expect("captured gateway logs")
    };
    assert_eq!(
        logs.contains(DIRECT_H1_DIAL_MARKER),
        direct,
        "the request must have been served by the {} HTTP/1.1 transport",
        if direct { "direct" } else { "reqwest" }
    );
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
        resp.headers.get("via").and_then(|v| v.to_str().ok()),
        Some("1.1 ferrum-edge"),
        "a streamed HTTP/1.1 backend response must carry an HTTP/1.1 Via (RFC 9110 §7.6.3)"
    );
    assert_eq!(
        request_conns.load(Ordering::SeqCst),
        1,
        "sequential requests must reuse one keep-alive backend connection (direct={direct})"
    );
    assert_transport(&harness, direct).await;
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

/// TLS keep-alive backend that offers BOTH `h2` and `http/1.1` in ALPN and
/// records, per connection that carried an HTTP/1.1 request, the protocol it
/// negotiated and how many requests it served.
async fn spawn_tls_keepalive_backend(
    listener: TcpListener,
    cert_pem: &str,
    key_pem: &str,
) -> Arc<std::sync::Mutex<Vec<(Option<Vec<u8>>, Arc<AtomicU32>)>>> {
    use rustls::pki_types::pem::PemObject;
    let chain: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|c| c.ok())
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("key");
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .expect("cert");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let connections = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let record = Arc::clone(&record);
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                let served = Arc::new(AtomicU32::new(0));
                let registered = Arc::new(AtomicBool::new(false));
                let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                    if !registered.swap(true, Ordering::SeqCst) {
                        record
                            .lock()
                            .expect("record")
                            .push((alpn.clone(), Arc::clone(&served)));
                    }
                    served.fetch_add(1, Ordering::SeqCst);
                    async {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"tls"))))
                    }
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    connections
}

/// Two routes to one TLS backend that differ only in backend TLS settings must
/// never share a pooled connection, each must still reuse its own, and the
/// direct pool must never let the backend ALPN-select h2.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h1_isolates_tls_settings_and_never_negotiates_h2() {
    let ca = crate::scaffolding::certs::TestCa::new("h1-direct-root").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let connections =
        spawn_tls_keepalive_backend(reservation.into_listener(), &cert_pem, &key_pem).await;
    let ca_dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca_dir.path().join("backend-ca.pem");
    std::fs::write(&ca_path, &ca.cert_pem).expect("write ca");

    let route = |id: &str, path: &str, verify: bool| {
        let mut route = json!({
            "id": id,
            "listen_path": path,
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            // HTTP/1.1-only HTTPS backend: the direct pool's territory.
            "pool_enable_http2": false,
            "backend_tls_verify_server_cert": verify,
        });
        if verify {
            route["backend_tls_server_ca_cert_path"] = json!(ca_path.to_string_lossy());
        }
        route
    };
    let yaml = to_file_mode_yaml(&json!({
        "version": "1",
        "proxies": [route("verified", "/verified", true), route("unverified", "/unverified", false)],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    }));
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .pool_warmup_enabled(false)
        .log_level("debug")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");
    let client = harness.http_client().expect("client");

    for i in 0..3 {
        for path in ["/verified/x", "/unverified/x"] {
            let resp = client
                .get(&harness.proxy_url(path))
                .await
                .unwrap_or_else(|e| panic!("{path} request {i} failed: {e}"));
            assert_eq!(resp.status, 200, "{path} request {i}");
            assert_eq!(&resp.body_bytes[..], b"tls", "{path} request {i}");
        }
    }

    {
        let connections = connections.lock().expect("record");
        assert_eq!(
            connections.len(),
            2,
            "two TLS settings must use two pooled connections, each reused"
        );
        for (alpn, served) in connections.iter() {
            assert_eq!(
                alpn.as_deref(),
                Some(&b"http/1.1"[..]),
                "the direct HTTP/1.1 pool must never offer h2"
            );
            assert_eq!(served.load(Ordering::SeqCst), 3);
        }
    }
    assert_transport(&harness, true).await;
}

/// A backend that answers before reading the whole upload leaves the gateway's
/// connection still writing that upload. It must not be handed to another
/// request until the upload finishes: the next request has to get a fresh
/// connection instead of waiting behind someone else's upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn direct_h1_early_response_mid_upload_is_not_reused() {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let listener = reservation.into_listener();
    // Raw keep-alive backend: `/early` is answered 401 as soon as its head
    // arrives, then the connection keeps draining the chunked upload as it
    // trickles in and stays open for the next request. That keeps the
    // gateway's connection in "response done, request body still writing".
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut pending: Vec<u8> = Vec::new();
                loop {
                    let head_end = loop {
                        if let Some(i) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&pending[..head_end]).to_string();
                    pending.drain(..head_end);
                    if head.starts_with("PRI * HTTP/2.0") {
                        return;
                    }
                    if head.contains(" /early ") {
                        if stream
                            .write_all(
                                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\n\r\ndenied",
                            )
                            .await
                            .is_err()
                        {
                            return;
                        }
                        // Drain the chunked upload to its terminal chunk.
                        while !(pending.starts_with(b"0\r\n\r\n")
                            || pending.windows(7).any(|w| w == b"\r\n0\r\n\r\n"))
                        {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => pending.extend_from_slice(&buf[..n]),
                            }
                        }
                        let end = pending
                            .windows(5)
                            .position(|w| w == b"0\r\n\r\n")
                            .map_or(pending.len(), |i| i + 5);
                        pending.drain(..end);
                        continue;
                    }
                    if stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfast")
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    let harness = spawn_gateway(backend_port, true).await;
    let early_url = harness.proxy_url("/api/early");
    let fast_url = harness.proxy_url("/api/fast");

    // Client 1 trickles a ~3 s chunked upload.
    let trickle = futures_util::stream::unfold(0u32, |i| async move {
        if i >= 30 {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Some((
            Ok::<_, std::io::Error>(Bytes::from(vec![b'u'; 1024])),
            i + 1,
        ))
    });
    let uploader = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("uploader");
    let early = tokio::spawn(async move {
        uploader
            .post(early_url)
            .body(reqwest::Body::wrap_stream(trickle))
            .send()
            .await
            .map(|resp| resp.status())
    });
    // Give the gateway time to relay the early 401 while the upload continues.
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;

    let started = std::time::Instant::now();
    let client = harness.http_client().expect("client");
    let fast = client.get(&fast_url).await.expect("fast request");
    let elapsed = started.elapsed();
    assert_eq!(fast.status, 200);
    assert_eq!(&fast.body_bytes[..], b"fast");
    assert!(
        elapsed < std::time::Duration::from_millis(1000),
        "the second request waited {elapsed:?} — it was handed a connection still writing another client's upload"
    );
    let early_status = early.await.expect("uploader task");
    if let Ok(status) = early_status {
        assert_eq!(status, 401);
    }
    assert_transport(&harness, true).await;
}

/// How the HTTP/1.1 backend saw a chunked upload end (issue #6022).
#[derive(Debug, PartialEq, Eq)]
enum ChunkedUploadEnd {
    /// The terminal `0\r\n\r\n` chunk arrived: the backend saw a complete body.
    Complete,
    /// The connection closed or failed before the terminal chunk.
    Aborted,
    /// The upload was not chunked, so this fixture cannot judge it.
    NotChunked(String),
}

/// Raw HTTP/1.1 backend that answers every `POST /upload` with a complete `200`
/// as soon as the request head arrives, then reads the rest of the chunked
/// upload and reports how it ended. Anything else, such as the gateway's h2c
/// capability probe, is ignored.
fn spawn_early_answer_upload_backend(
    listener: TcpListener,
) -> tokio::sync::mpsc::UnboundedReceiver<ChunkedUploadEnd> {
    let (ends_tx, ends_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let ends_tx = ends_tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let mut pending: Vec<u8> = Vec::new();
                let head_end = loop {
                    if let Some(i) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&pending[..head_end]).into_owned();
                let head = head.to_ascii_lowercase();
                pending.drain(..head_end);
                if !head.starts_with("post /upload ") {
                    return;
                }
                if !head.contains("transfer-encoding: chunked") {
                    let _ = ends_tx.send(ChunkedUploadEnd::NotChunked(head));
                    return;
                }
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .is_err()
                {
                    return;
                }
                loop {
                    if pending.starts_with(b"0\r\n\r\n")
                        || pending.windows(7).any(|w| w == b"\r\n0\r\n\r\n")
                    {
                        let _ = ends_tx.send(ChunkedUploadEnd::Complete);
                        return;
                    }
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            let _ = ends_tx.send(ChunkedUploadEnd::Aborted);
                            return;
                        }
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                    }
                }
            });
        }
    });
    ends_rx
}

/// Issue #6022: hyper reports an HTTP/2 client's `RST_STREAM(NO_ERROR)` as a
/// clean end of the request body. An upload relayed to an HTTP/1.1 backend must
/// still end as an aborted body, never with the terminal chunk that makes a
/// truncated upload look complete. An explicit client CANCEL ends the same way.
///
/// The backend answers before the upload ends and the client reads that whole
/// response before it resets, so only the relayed upload can carry the reset to
/// the backend. `max_request_body_bytes == 0` relays the upload through
/// `CountingIncoming`, anything else through `SizeLimitedIncoming`. A non-zero
/// `write_timeout_ms` moves the client body into the upload pump, which must
/// inherit the adapter's END_STREAM requirement.
async fn h2_client_reset_reaches_h1_backend_as_aborted_upload(
    direct: bool,
    max_request_body_bytes: u64,
    write_timeout_ms: u64,
) {
    let reservation = reserve_port().await.expect("reserve port");
    let backend_port = reservation.port;
    let mut upload_ends = spawn_early_answer_upload_backend(reservation.into_listener());
    let yaml = to_file_mode_yaml(&json!({
        "version": "1",
        "proxies": [{
            "id": "h1-upload-reset",
            "listen_path": "/api",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": write_timeout_ms,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    }));
    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .env(
            "FERRUM_POOL_HTTP1_DIRECT",
            if direct { "true" } else { "false" },
        )
        .env(
            "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
            max_request_body_bytes.to_string(),
        )
        .pool_warmup_enabled(false)
        .log_level("debug")
        .capture_output()
        .spawn()
        .await
        .expect("spawn gateway");

    let port = reqwest::Url::parse(harness.proxy_base_url())
        .expect("frontend URL")
        .port()
        .expect("frontend port");
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("h2c socket");
    let (client, connection) = h2::client::handshake(socket).await.expect("frontend h2");
    let driver = tokio::spawn(connection);
    for reason in [h2::Reason::NO_ERROR, h2::Reason::CANCEL] {
        let mut client = client.clone().ready().await.expect("client ready");
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("http://localhost:{port}/api/upload"))
            .header("content-type", "application/octet-stream")
            .body(())
            .expect("request");
        let (response, mut upload) = client.send_request(request, false).expect("open upload");
        upload
            .send_data(Bytes::from_static(b"partial upload"), false)
            .expect("initial DATA");
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), response)
            .await
            .expect("early response timeout")
            .expect("early response");
        assert_eq!(response.status(), 200, "{reason:?}");
        let mut body = response.into_body();
        let read_body = async {
            while let Some(chunk) = body.data().await {
                chunk.expect("early response body");
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), read_body)
            .await
            .expect("the early response must complete");
        upload.send_reset(reason);

        let end = tokio::time::timeout(std::time::Duration::from_secs(10), upload_ends.recv())
            .await
            .unwrap_or_else(|_| panic!("the backend upload never ended after a {reason:?} reset"))
            .expect("backend upload observer");
        assert_eq!(
            end,
            ChunkedUploadEnd::Aborted,
            "a client {reason:?} reset must reach the backend as an aborted upload, \
             never as a complete chunked body"
        );
    }
    driver.abort();
    let _ = driver.await;
    assert_transport(&harness, direct).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_client_reset_reaches_reqwest_h1_backend_as_aborted_upload() {
    // reqwest, `CountingIncoming` polled in place.
    h2_client_reset_reaches_h1_backend_as_aborted_upload(false, 0, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_client_reset_reaches_reqwest_h1_backend_through_upload_pump() {
    // reqwest, `SizeLimitedIncoming` with the upload pump.
    h2_client_reset_reaches_h1_backend_as_aborted_upload(false, 1_048_576, 5_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_client_reset_reaches_direct_h1_backend_as_aborted_upload() {
    // Direct HTTP/1.1 pool, `SizeLimitedIncoming` polled in place.
    h2_client_reset_reaches_h1_backend_as_aborted_upload(true, 1_048_576, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_client_reset_reaches_direct_h1_backend_through_upload_pump() {
    // Direct HTTP/1.1 pool, `CountingIncoming` with the upload pump.
    h2_client_reset_reaches_h1_backend_as_aborted_upload(true, 0, 5_000).await;
}
