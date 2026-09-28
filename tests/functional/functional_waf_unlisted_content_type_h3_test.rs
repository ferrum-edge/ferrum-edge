//! `waf` `on_unlisted_content_type: block` end to end on HTTP/3.
//!
//! The H3 client sends request bodies as DATA frames without a
//! `Content-Length`, so the WAF cannot learn from the request headers that a
//! body is coming: the refusal must come from the buffered final-body
//! decision. A non-empty unlisted body (declared-length or not, and with no
//! `Content-Type` at all) is refused before it reaches the origin, while an
//! empty upload, a bodyless method, and a listed type still pass.
//!
//! Run with:
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests waf_unlisted_content_type_h3 -- --ignored --nocapture
//! ```

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;

use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;

const SQLI_JSON: &[u8] = br#"{"id":"1 UNION SELECT password FROM users"}"#;

fn write_frontend_certs(scratch: &std::path::Path) -> (String, String) {
    let ca = TestCa::new("h3-waf-unlisted-gateway").expect("gateway CA");
    let (cert, key) = ca.valid().expect("gateway leaf");
    let cert_path = scratch.join("gateway.cert.pem");
    let key_path = scratch.join("gateway.key.pem");
    std::fs::write(&cert_path, cert).expect("write gateway cert");
    std::fs::write(&key_path, key).expect("write gateway key");
    (
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// HTTP/1.1 origin that counts the `/items` requests it receives, so a
/// refused body is proven never to have been forwarded.
fn spawn_counting_backend(listener: tokio::net::TcpListener) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let backend_hits = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = Arc::clone(&backend_hits);
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        let counted = request.uri().path() == "/items";
                        let _ = request.into_body().collect().await;
                        if counted {
                            hits.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    hits
}

async fn spawn_gateway(backend_port: u16) -> (GatewayHarness, u16, tempfile::TempDir) {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-unlisted",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "h3-unlisted-waf"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "h3-unlisted-waf",
            "plugin_name": "waf",
            "scope": "proxy",
            "proxy_id": "h3-unlisted",
            "enabled": true,
            "config": {
                "mode": "enforce",
                "default_rule_action": "enforce",
                "on_unlisted_content_type": "block"
            }
        }]
    });
    let yaml = serde_yaml::to_string(&config).expect("serialize config");
    let mut last_error = String::new();
    for _ in 0..5 {
        let reservation = reserve_port().await.expect("reserve H3 port");
        let https_port = reservation.drop_and_take_port();
        let scratch = tempfile::tempdir().expect("gateway scratch dir");
        let (cert_path, key_path) = write_frontend_certs(scratch.path());
        match GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("warn")
            .capture_output()
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
            .pool_warmup_enabled(false)
            .spawn()
            .await
        {
            Ok(gateway) => return (gateway, https_port, scratch),
            Err(error) => last_error = error.to_string(),
        }
    }
    panic!("failed to spawn H3 WAF gateway: {last_error}");
}

/// Retries only transport failures (the QUIC listener may still be coming
/// up); any HTTP response, including a rejection, is returned as-is.
async fn request_with_retry(client: &Http3Client, url: &str, options: GetOptions) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return response,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            Err(error) => panic!("H3 request never completed: {error}"),
        }
    }
}

fn post(content_type: Option<&str>, body: &'static [u8]) -> GetOptions {
    let mut options = GetOptions::default()
        .method(Method::POST)
        .body(Bytes::from_static(body));
    if let Some(content_type) = content_type {
        options = options.header("content-type", content_type);
    }
    options
}

#[tokio::test]
#[ignore]
async fn h3_unlisted_content_type_block_refuses_before_the_origin() {
    let backend_reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = backend_reservation.port;
    let hits = spawn_counting_backend(backend_reservation.into_listener());

    let (_gateway, https_port, _scratch) = spawn_gateway(backend_port).await;
    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://127.0.0.1:{https_port}/items");

    // Readiness: a bodyless GET is not governed and reaches the origin.
    let before = hits.load(Ordering::SeqCst);
    let ready = request_with_retry(&client, &url, GetOptions::default()).await;
    assert_eq!(ready.status, StatusCode::OK);
    assert!(hits.load(Ordering::SeqCst) > before);

    // Unlisted bodies sent without Content-Length, including a missing
    // Content-Type.
    for content_type in [Some("application/octet-stream"), Some("text/csv"), None] {
        let before = hits.load(Ordering::SeqCst);
        let response = request_with_retry(&client, &url, post(content_type, SQLI_JSON)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{content_type:?}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before,
            "{content_type:?}: a refused body reached the origin"
        );
    }

    // A declared length changes nothing.
    let before = hits.load(Ordering::SeqCst);
    let declared = post(Some("application/octet-stream"), SQLI_JSON)
        .header("content-length", SQLI_JSON.len().to_string());
    let response = request_with_retry(&client, &url, declared).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::SeqCst), before);

    // An empty unlisted upload and a listed type pass.
    for (content_type, body) in [
        ("application/octet-stream", &b""[..]),
        ("application/json", &br#"{"name":"widget"}"#[..]),
    ] {
        let before = hits.load(Ordering::SeqCst);
        let response = request_with_retry(&client, &url, post(Some(content_type), body)).await;
        assert_eq!(response.status, StatusCode::OK, "{content_type}");
        assert!(hits.load(Ordering::SeqCst) > before, "{content_type}");
    }

    // A listed type is scanned, so the same payload is refused by the rules.
    let before = hits.load(Ordering::SeqCst);
    let listed_sqli = post(Some("application/json"), SQLI_JSON);
    let response = request_with_retry(&client, &url, listed_sqli).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert_eq!(hits.load(Ordering::SeqCst), before);
}
