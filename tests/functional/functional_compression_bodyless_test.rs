//! Issue #2356: compression must not encode HEAD or 205 empty wire bodies.
//!
//! Covers H1 / H2 / H3 frontends for:
//! - gzip and Brotli response negotiation/round trips
//! - `205` with absent and zero backend `Content-Length`
//! - `HEAD` with present and absent backend `Content-Length`
//!
//! Asserts no body bytes are emitted and pins
//! `Content-Length` / `Content-Encoding` / `Vary` behavior.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{Method, StatusCode, header};
use std::io::Read as _;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

const HEAD_REPR_LEN: usize = 1024;
const CONTROL_BODY: &str = r#"{"ok":true,"padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "compression-bodyless"
    listen_path: "/cmp"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    pool_enable_http2: true
    plugins:
      - plugin_config_id: "compression-bodyless-plugin"

consumers: []
plugin_configs:
  - id: "compression-bodyless-plugin"
    plugin_name: compression
    scope: proxy
    proxy_id: "compression-bodyless"
    enabled: true
    config:
      algorithms: ["gzip", "br"]
      min_content_length: 256
      remove_accept_encoding: true
"#
    )
}

async fn spawn_bodyless_backend(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let Ok(n) = stream.read(&mut buf).await else {
                return;
            };
            if n == 0 {
                return;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let request_line = req.lines().next().unwrap_or("");
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let path = parts.next().unwrap_or("");

            let response = match (method, path) {
                ("GET", "/reset-absent") => "HTTP/1.1 205 Reset Content\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n"
                    .to_string(),
                ("GET", "/reset-zero") => "HTTP/1.1 205 Reset Content\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\
                     \r\n"
                    .to_string(),
                ("HEAD", "/head-present") => {
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {HEAD_REPR_LEN}\r\n\
                         Connection: close\r\n\
                         \r\n"
                    )
                }
                ("HEAD", "/head-absent") => "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/json\r\n\
                     Connection: close\r\n\
                     \r\n"
                    .to_string(),
                ("GET", "/control") => {
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n\
                         {CONTROL_BODY}",
                        CONTROL_BODY.len()
                    )
                }
                _ => "HTTP/1.1 404 Not Found\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\
                     \r\n"
                    .to_string(),
            };

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn spawn_gateway(backend_port: u16, extra_env: &[(&str, &str)]) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: usize = 5;
    let mut last_error = String::new();

    for _ in 0..MAX_ATTEMPTS {
        let reservation = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let https_port = match reservation.local_addr() {
            Ok(address) => address.port(),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        drop(reservation);

        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false");
        for (name, value) in extra_env {
            builder = builder.env(*name, *value);
        }
        let result = builder.spawn().await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!(
        "failed to spawn compression bodyless gateway after {MAX_ATTEMPTS} attempts: {last_error}"
    );
}

fn content_length(headers: &reqwest::header::HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

fn h3_content_length(headers: &http::HeaderMap) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
}

fn content_encoding(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
}

fn h3_content_encoding(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase())
}

fn has_accept_encoding_vary(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|member| member.trim().eq_ignore_ascii_case("accept-encoding"))
}

fn h3_has_accept_encoding_vary(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|member| member.trim().eq_ignore_ascii_case("accept-encoding"))
}

async fn h3_request_until_ready(
    client: &Http3Client,
    url: &str,
    method: Method,
    accept_encoding: &str,
) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    let options = GetOptions::default()
        .method(method.clone())
        .header("Accept-Encoding", accept_encoding);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 {method} {url} did not complete: {error}"),
        }
    }
}

fn assert_compression_round_trip(protocol: &str, encoding: &str, compressed: &[u8]) {
    let mut decoded = Vec::new();
    match encoding {
        "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(compressed);
            decoder
                .read_to_end(&mut decoded)
                .unwrap_or_else(|error| panic!("{protocol} gzip decode failed: {error}"));
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(compressed, 4096);
            decoder
                .read_to_end(&mut decoded)
                .unwrap_or_else(|error| panic!("{protocol} Brotli decode failed: {error}"));
        }
        other => panic!("unsupported test encoding {other}"),
    }
    assert_eq!(
        decoded,
        CONTROL_BODY.as_bytes(),
        "{protocol} {encoding} round trip"
    );
}

async fn assert_h1_h2_compression(
    client: &reqwest::Client,
    url: &str,
    protocol: &str,
    encoding: &str,
) {
    let response = client
        .get(url)
        .header("Accept-Encoding", encoding)
        .send()
        .await
        .unwrap_or_else(|error| panic!("{protocol} {encoding} request failed: {error}"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        content_encoding(response.headers()).as_deref(),
        Some(encoding),
        "{protocol} must select {encoding}"
    );
    assert!(has_accept_encoding_vary(response.headers()));
    let compressed = response
        .bytes()
        .await
        .unwrap_or_else(|error| panic!("{protocol} {encoding} body read failed: {error}"));
    assert_compression_round_trip(protocol, encoding, &compressed);
}

async fn assert_h1_h2_205(
    client: &reqwest::Client,
    url: &str,
    protocol: &str,
    backend_cl: Option<usize>,
) {
    let response = client
        .get(url)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap_or_else(|e| panic!("{protocol} GET {url} failed: {e}"));
    assert_eq!(
        response.status(),
        reqwest::StatusCode::RESET_CONTENT,
        "{protocol} {url} status"
    );
    assert!(
        content_encoding(response.headers()).is_none(),
        "{protocol} {url} must not set Content-Encoding (got {:?})",
        content_encoding(response.headers())
    );
    assert!(
        !has_accept_encoding_vary(response.headers()),
        "{protocol} {url} must not nominate Vary: Accept-Encoding"
    );
    let cl = content_length(response.headers());
    // Gateway compression must not invent an encoded-empty length. Backend
    // absent/zero length must not become a nonzero gzip-member length.
    match backend_cl {
        Some(0) => assert!(
            cl.is_none() || cl == Some(0),
            "{protocol} {url} CL must stay absent/zero (got {cl:?})"
        ),
        None => assert!(
            cl.is_none() || cl == Some(0),
            "{protocol} {url} absent-backend CL must not become encoded-empty (got {cl:?})"
        ),
        Some(other) => panic!("unexpected backend CL fixture {other}"),
    }
    let body = response
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("{protocol} {url} body read failed: {e}"));
    assert!(
        body.is_empty(),
        "{protocol} {url} must emit no body bytes, got {} bytes",
        body.len()
    );
}

async fn assert_h1_h2_head(
    client: &reqwest::Client,
    url: &str,
    protocol: &str,
    expected_cl: Option<usize>,
) {
    let response = client
        .head(url)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .unwrap_or_else(|e| panic!("{protocol} HEAD {url} failed: {e}"));
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "{protocol} HEAD {url} status"
    );
    assert!(
        content_encoding(response.headers()).is_none(),
        "{protocol} HEAD {url} must not set Content-Encoding (got {:?})",
        content_encoding(response.headers())
    );
    assert!(
        !has_accept_encoding_vary(response.headers()),
        "{protocol} HEAD {url} must not nominate Vary: Accept-Encoding"
    );
    let cl = content_length(response.headers());
    match expected_cl {
        Some(len) => assert_eq!(
            cl,
            Some(len),
            "{protocol} HEAD {url} must preserve backend Content-Length"
        ),
        // Absent backend CL: keep absent or an identity-empty 0. Never invent
        // an encoded-empty gzip-member length.
        None => assert!(
            cl.is_none() || cl == Some(0),
            "{protocol} HEAD {url} must not invent encoded-empty Content-Length (got {cl:?})"
        ),
    }
    let body = response
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("{protocol} HEAD {url} body read failed: {e}"));
    assert!(
        body.is_empty(),
        "{protocol} HEAD {url} must emit no body bytes, got {} bytes",
        body.len()
    );
}

#[ignore]
#[tokio::test]
async fn functional_compression_skips_head_and_205_across_h1_h2_h3() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bodyless compression backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();
    tokio::spawn(spawn_bodyless_backend(backend_listener));

    let (mut gateway, https_port) = spawn_gateway(backend_port, &[]).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("H1 client");
    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("H2 client");

    let reset_absent = gateway.proxy_url("/cmp/reset-absent");
    let reset_zero = gateway.proxy_url("/cmp/reset-zero");
    let head_present = gateway.proxy_url("/cmp/head-present");
    let head_absent = gateway.proxy_url("/cmp/head-absent");
    let control = gateway.proxy_url("/cmp/control");

    // Ordinary responses negotiate both codecs on both TCP HTTP versions.
    for encoding in ["gzip", "br"] {
        assert_h1_h2_compression(&h1, &control, "H1", encoding).await;
        assert_h1_h2_compression(&h2, &control, "H2", encoding).await;
    }

    // --- H1 ---
    assert_h1_h2_205(&h1, &reset_absent, "H1", None).await;
    assert_h1_h2_205(&h1, &reset_zero, "H1", Some(0)).await;
    assert_h1_h2_head(&h1, &head_present, "H1", Some(HEAD_REPR_LEN)).await;
    assert_h1_h2_head(&h1, &head_absent, "H1", None).await;

    // --- H2 ---
    assert_h1_h2_205(&h2, &reset_absent, "H2", None).await;
    assert_h1_h2_205(&h2, &reset_zero, "H2", Some(0)).await;
    assert_h1_h2_head(&h2, &head_present, "H2", Some(HEAD_REPR_LEN)).await;
    assert_h1_h2_head(&h2, &head_absent, "H2", None).await;

    // --- H3 ---
    let h3 = Http3Client::insecure().expect("H3 client");
    let h3_reset_absent = format!("https://localhost:{https_port}/cmp/reset-absent");
    let h3_reset_zero = format!("https://localhost:{https_port}/cmp/reset-zero");
    let h3_head_present = format!("https://localhost:{https_port}/cmp/head-present");
    let h3_head_absent = format!("https://localhost:{https_port}/cmp/head-absent");
    let h3_control = format!("https://localhost:{https_port}/cmp/control");

    // Native H3 uses the same negotiation and body transform for both codecs.
    for encoding in ["gzip", "br"] {
        let response = h3_request_until_ready(&h3, &h3_control, Method::GET, encoding).await;
        assert_eq!(response.status, StatusCode::OK, "H3 {encoding} status");
        assert_eq!(
            h3_content_encoding(&response.headers).as_deref(),
            Some(encoding),
            "H3 must select {encoding}"
        );
        assert!(h3_has_accept_encoding_vary(&response.headers));
        assert_compression_round_trip("H3", encoding, &response.body_bytes);
    }

    for (url, backend_cl) in [
        (h3_reset_absent.as_str(), None),
        (h3_reset_zero.as_str(), Some(0usize)),
    ] {
        let response = h3_request_until_ready(&h3, url, Method::GET, "gzip").await;
        assert_eq!(response.status, StatusCode::RESET_CONTENT, "H3 {url}");
        assert!(
            response.body_bytes.is_empty(),
            "H3 {url} must emit no body bytes"
        );
        assert!(
            h3_content_encoding(&response.headers).is_none(),
            "H3 {url} must not set Content-Encoding"
        );
        assert!(
            !h3_has_accept_encoding_vary(&response.headers),
            "H3 {url} must not nominate Vary: Accept-Encoding"
        );
        let cl = h3_content_length(&response.headers);
        assert!(
            cl.is_none() || cl == Some(0),
            "H3 {url} CL must stay absent/zero for backend_cl={backend_cl:?} (got {cl:?})"
        );
    }

    let h3_head = h3_request_until_ready(&h3, &h3_head_present, Method::HEAD, "gzip").await;
    assert_eq!(h3_head.status, StatusCode::OK);
    assert!(
        h3_head.body_bytes.is_empty(),
        "H3 HEAD present must omit DATA"
    );
    assert!(h3_content_encoding(&h3_head.headers).is_none());
    assert!(!h3_has_accept_encoding_vary(&h3_head.headers));
    assert_eq!(h3_content_length(&h3_head.headers), Some(HEAD_REPR_LEN));

    let h3_head_abs = h3_request_until_ready(&h3, &h3_head_absent, Method::HEAD, "gzip").await;
    assert_eq!(h3_head_abs.status, StatusCode::OK);
    assert!(
        h3_head_abs.body_bytes.is_empty(),
        "H3 HEAD absent must omit DATA"
    );
    assert!(h3_content_encoding(&h3_head_abs.headers).is_none());
    assert!(!h3_has_accept_encoding_vary(&h3_head_abs.headers));
    let h3_abs_cl = h3_content_length(&h3_head_abs.headers);
    assert!(
        h3_abs_cl.is_none() || h3_abs_cl == Some(0),
        "H3 HEAD absent must not invent encoded-empty Content-Length (got {h3_abs_cl:?})"
    );

    gateway.shutdown();

    // The process-wide codec gates intersect the plugin's per-proxy algorithm
    // list. Disable gzip while leaving Brotli enabled and verify the real
    // runtime plugin cache observes both sides of that policy.
    let (mut policy_gateway, _) = spawn_gateway(
        backend_port,
        &[
            ("FERRUM_COMPRESSION_GZIP_ENABLED", "false"),
            ("FERRUM_COMPRESSION_BROTLI_ENABLED", "true"),
        ],
    )
    .await;
    policy_gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("policy gateway port ready");
    let policy_control = policy_gateway.proxy_url("/cmp/control");

    let gzip_disabled = h1
        .get(&policy_control)
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .expect("gzip-disabled request");
    assert_eq!(gzip_disabled.status(), reqwest::StatusCode::OK);
    assert!(
        content_encoding(gzip_disabled.headers()).is_none(),
        "globally disabled gzip must not be selected"
    );
    assert_eq!(
        gzip_disabled.bytes().await.expect("identity body"),
        CONTROL_BODY.as_bytes()
    );

    assert_h1_h2_compression(&h1, &policy_control, "H1 global policy", "br").await;
    policy_gateway.shutdown();
}
