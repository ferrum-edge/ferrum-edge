//! HTTP/3 HEAD/GET contract for `request_termination` synthetic responses.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{Method, StatusCode};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::sleep;

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "h3-termination"
    listen_path: "/term"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "h3-termination-plugin"
consumers: []
plugin_configs:
  - id: "h3-termination-plugin"
    plugin_name: request_termination
    scope: proxy
    proxy_id: "h3-termination"
    enabled: true
    config:
      status_code: 503
      content_type: application/json
      message: "h3 maintenance window"
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 1
"#
    )
}

async fn h3_request_until_ready(client: &Http3Client, url: &str, method: Method) -> Http3Response {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match client
            .get_with_options(url, GetOptions::default().method(method.clone()))
            .await
        {
            Ok(response) => return response,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 {method} {url} did not complete: {error}"),
        }
    }
}

async fn spawn_h3_gateway(backend_port: u16) -> (TestGateway, u16) {
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

        let result = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .spawn()
            .await;
        match result {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!(
        "failed to spawn request_termination H3 gateway after {MAX_ATTEMPTS} attempts: {last_error}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_request_termination_h3_head_omits_data_and_get_keeps_body() {
    // Backend must never be contacted — bind and leave it idle so any dial fails loudly.
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind idle backend");
    let backend_port = backend_listener.local_addr().expect("backend addr").port();

    let (mut gateway, https_port) = spawn_h3_gateway(backend_port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/term/anything");

    let get = h3_request_until_ready(&client, &url, Method::GET).await;
    assert_eq!(get.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        get.body_text().contains("h3 maintenance window"),
        "GET must receive the configured termination body, got {}",
        get.body_text()
    );
    let representation_len = get.body_bytes.len();
    assert!(representation_len > 0);

    let head = h3_request_until_ready(&client, &url, Method::HEAD).await;
    assert_eq!(head.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        head.body_bytes.is_empty(),
        "HEAD must not receive DATA/content bytes"
    );
    let head_len = head
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    assert_eq!(
        head_len,
        Some(representation_len),
        "HEAD Content-Length must match the GET representation"
    );

    // Idle backend accept queue must stay empty — termination short-circuits.
    assert!(
        backend_listener.local_addr().is_ok(),
        "backend listener must remain bound"
    );

    gateway.shutdown();
}
