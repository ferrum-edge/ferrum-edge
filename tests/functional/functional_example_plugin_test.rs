//! Hosted-only H1/H2/H3 lifecycle coverage for the shipped custom plugin.
//!
//! Run: `cargo build --bin ferrum-edge && cargo test --test functional_tests functional_example_plugin -- --ignored --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::reserve_colocated_tcp_udp;

use http::{HeaderMap, Method, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// File mode intentionally probes this backend with an untagged h2c preface
// during startup. Tag client-driven contract traffic so backend accounting
// still detects 404/405 leaks without treating that probe as a routed request.
const CONTRACT_REQUEST_HEADER: &str = "x-example-contract-request";

struct HeaderEchoBackend {
    port: u16,
    contract_requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl HeaderEchoBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind example backend");
        let port = listener.local_addr().expect("example backend addr").port();
        let contract_requests = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn(serve_header_echo(listener, Arc::clone(&contract_requests)));
        sleep(Duration::from_millis(100)).await;
        Self {
            port,
            contract_requests,
            task,
        }
    }

    fn contract_requests(&self) -> Vec<String> {
        self.contract_requests
            .lock()
            .expect("contract request lock")
            .clone()
    }
}

impl Drop for HeaderEchoBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_header_echo(listener: TcpListener, contract_requests: Arc<Mutex<Vec<String>>>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let contract_requests = Arc::clone(&contract_requests);
        tokio::spawn(async move {
            let mut request = Vec::with_capacity(2048);
            let mut chunk = [0u8; 1024];
            loop {
                let read =
                    tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await;
                let Ok(Ok(read)) = read else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if request.len() > 32 * 1024 {
                    return;
                }
            }

            let request = String::from_utf8_lossy(&request);
            let observed = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-custom-gateway")
                    .then(|| value.trim())
            });
            if let Some(contract_request) = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case(CONTRACT_REQUEST_HEADER)
                    .then(|| value.trim())
            }) {
                let mut recorded = contract_requests.lock().expect("contract request lock");
                if !recorded
                    .iter()
                    .any(|request| request.as_str() == contract_request)
                {
                    // Retries retain one ID because the contract is about the
                    // logical client request, not backend transport attempts.
                    recorded.push(contract_request.to_string());
                }
            }
            let observed = observed.unwrap_or("missing");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\nX-Backend-Observed: {observed}\r\nConnection: close\r\n\r\nok"
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "global-example-route"
    listen_path: "/global-example"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: ["GET"]
  - id: "scoped-example-route"
    listen_path: "/scoped-example"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: ["GET"]
    plugins:
      - plugin_config_id: "scoped-example"
consumers: []
plugin_configs:
  - id: "global-example"
    plugin_name: example_plugin
    scope: global
    enabled: true
    config:
      header_value: "global-value"
  - id: "scoped-example"
    plugin_name: example_plugin
    scope: proxy
    proxy_id: "scoped-example-route"
    enabled: true
    config:
      header_value: "scoped-value"
expected_resource_counts:
  proxies: 2
  consumers: 0
  upstreams: 0
  plugin_configs: 2
"#
    )
}

async fn start_h3_gateway_with_retry(backend_port: u16) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_error = String::new();

    for attempt in 1..=MAX_ATTEMPTS {
        let (https_tcp, https_udp) = reserve_colocated_tcp_udp()
            .await
            .expect("reserve colocated HTTPS port");
        let https_port = https_tcp.port;
        assert_eq!(https_port, https_udp.port);
        drop(https_tcp);
        drop(https_udp);

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            // The outer loop owns retries so each attempt gets a fresh TCP/UDP
            // HTTPS port and a fresh harness temp directory.
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .spawn()
            .await;

        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    panic!("start H3 example gateway after retries: {last_error}");
}

fn assert_matched_headers(headers: &HeaderMap, expected: &str) {
    assert_eq!(
        headers
            .get("x-backend-observed")
            .and_then(|value| value.to_str().ok()),
        Some(expected),
        "before_proxy request header must reach the backend"
    );
    assert_eq!(
        headers
            .get("x-custom-gateway")
            .and_then(|value| value.to_str().ok()),
        Some(expected),
        "after_proxy response header must reach the client"
    );
}

fn assert_early_response_has_no_example_header(headers: &HeaderMap) {
    assert!(
        !headers.contains_key("x-custom-gateway"),
        "404/405 must return before global or scoped example hooks"
    );
    assert!(
        !headers.contains_key("x-backend-observed"),
        "404/405 must not reach the backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_example_plugin_h1_h2_matched_404_and_405_contract() {
    let backend = HeaderEchoBackend::start().await;
    let mut gateway = TestGateway::builder()
        .mode_file(build_config(backend.port))
        .log_level("warn")
        .spawn()
        .await
        .expect("start H1/H2 example gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("example proxy port ready");

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H1 client");
    for (path, expected, contract_request) in [
        ("/global-example/ok", "global-value", "h1-global"),
        ("/scoped-example/ok", "scoped-value", "h1-scoped"),
    ] {
        let response = h1
            .get(gateway.proxy_url(path))
            .header(CONTRACT_REQUEST_HEADER, contract_request)
            .send()
            .await
            .expect("H1 matched request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_matched_headers(response.headers(), expected);
    }
    let h1_miss = h1
        .get(gateway.proxy_url("/unmatched-example"))
        .header(CONTRACT_REQUEST_HEADER, "h1-miss")
        .send()
        .await
        .expect("H1 route miss");
    assert_eq!(h1_miss.status(), reqwest::StatusCode::NOT_FOUND);
    assert_early_response_has_no_example_header(h1_miss.headers());
    let h1_method = h1
        .post(gateway.proxy_url("/global-example/blocked"))
        .header(CONTRACT_REQUEST_HEADER, "h1-method")
        .send()
        .await
        .expect("H1 method rejection");
    assert_eq!(h1_method.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_early_response_has_no_example_header(h1_method.headers());

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H2 client");
    for (path, expected, contract_request) in [
        ("/global-example/ok", "global-value", "h2-global"),
        ("/scoped-example/ok", "scoped-value", "h2-scoped"),
    ] {
        let response = h2
            .get(gateway.proxy_url(path))
            .header(CONTRACT_REQUEST_HEADER, contract_request)
            .send()
            .await
            .expect("H2 matched request");
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_matched_headers(response.headers(), expected);
    }
    let h2_miss = h2
        .get(gateway.proxy_url("/unmatched-example"))
        .header(CONTRACT_REQUEST_HEADER, "h2-miss")
        .send()
        .await
        .expect("H2 route miss");
    assert_eq!(h2_miss.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_miss.status(), reqwest::StatusCode::NOT_FOUND);
    assert_early_response_has_no_example_header(h2_miss.headers());
    let h2_method = h2
        .post(gateway.proxy_url("/scoped-example/blocked"))
        .header(CONTRACT_REQUEST_HEADER, "h2-method")
        .send()
        .await
        .expect("H2 method rejection");
    assert_eq!(h2_method.version(), reqwest::Version::HTTP_2);
    assert_eq!(h2_method.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_early_response_has_no_example_header(h2_method.headers());

    assert_eq!(
        backend.contract_requests(),
        vec![
            String::from("h1-global"),
            String::from("h1-scoped"),
            String::from("h2-global"),
            String::from("h2-scoped"),
        ],
        "only matched H1/H2 contract requests reach backend"
    );
    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_example_plugin_h3_matched_404_and_405_contract() {
    let backend = HeaderEchoBackend::start().await;
    let (mut gateway, https_port) = start_h3_gateway_with_retry(backend.port).await;

    let client = Http3Client::insecure().expect("H3 client");
    let first_url = format!("https://localhost:{https_port}/global-example/ok");
    let deadline = Instant::now() + Duration::from_secs(10);
    let first = loop {
        match client
            .get_with_options(
                &first_url,
                GetOptions::default().header(CONTRACT_REQUEST_HEADER, "h3-global"),
            )
            .await
        {
            Ok(response) => break response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 example request did not complete: {error}"),
        }
    };
    assert_eq!(first.status, StatusCode::OK);
    assert_matched_headers(&first.headers, "global-value");

    let scoped = client
        .get_with_options(
            &format!("https://localhost:{https_port}/scoped-example/ok"),
            GetOptions::default().header(CONTRACT_REQUEST_HEADER, "h3-scoped"),
        )
        .await
        .expect("H3 scoped matched request");
    assert_eq!(scoped.status, StatusCode::OK);
    assert_matched_headers(&scoped.headers, "scoped-value");

    let miss = client
        .get_with_options(
            &format!("https://localhost:{https_port}/unmatched-example"),
            GetOptions::default().header(CONTRACT_REQUEST_HEADER, "h3-miss"),
        )
        .await
        .expect("H3 route miss");
    assert_eq!(miss.status, StatusCode::NOT_FOUND);
    assert_early_response_has_no_example_header(&miss.headers);

    let method = client
        .get_with_options(
            &format!("https://localhost:{https_port}/global-example/blocked"),
            GetOptions::default()
                .method(Method::POST)
                .header(CONTRACT_REQUEST_HEADER, "h3-method"),
        )
        .await
        .expect("H3 method rejection");
    assert_eq!(method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_early_response_has_no_example_header(&method.headers);

    assert_eq!(
        backend.contract_requests(),
        vec![String::from("h3-global"), String::from("h3-scoped")],
        "only matched H3 contract requests reach backend"
    );
    gateway.shutdown();
}
