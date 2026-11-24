//! End-to-end key_auth query credential parity across HTTP/1.1, HTTP/2, and HTTP/3.

use crate::common::{EchoServer, TestGateway, spawn_http_echo};
use crate::scaffolding::clients::{GetOptions, Http3Client};

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::net::TcpStream;

const VALID_QUERY: &str = "api%5Fkey=wrong&api_key=alpha%2Fbeta-0123456789&keep=1";
const INVALID_QUERY: &str = "api%5Fkey=wrong%2Fkey";

#[ignore]
#[tokio::test]
async fn key_auth_decodes_and_strips_query_credentials_on_h1_h2_h3() {
    let mut harness = KeyAuthQueryHarness::spawn().await;

    let (status, body) = http1_request(&harness, VALID_QUERY).await;
    assert_success_without_credentials(status, &body, "HTTP/1.1");
    let (status, body) = h2_request(&harness, VALID_QUERY).await;
    assert_success_without_credentials(status, &body, "HTTP/2");
    let (status, body) = h3_request(&harness, VALID_QUERY).await;
    assert_success_without_credentials(status, &body, "HTTP/3");

    assert_eq!(
        http1_request(&harness, INVALID_QUERY).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h2_request(&harness, INVALID_QUERY).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h3_request(&harness, INVALID_QUERY).await.0,
        StatusCode::UNAUTHORIZED
    );

    let client = Http3Client::insecure().expect("h3 client");
    let grpc = h3_request_with_retry(
        &client,
        &harness.h3_url(INVALID_QUERY),
        GetOptions::default()
            .method(Method::POST)
            .header("content-type", "application/grpc"),
    )
    .await;
    assert_eq!(grpc.status, StatusCode::OK, "gRPC errors ride on HTTP 200");
    assert_eq!(
        grpc.headers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("16"),
        "invalid H3 gRPC key must use UNAUTHENTICATED framing"
    );

    harness.shutdown();
}

fn assert_success_without_credentials(status: StatusCode, body: &str, protocol: &str) {
    assert_eq!(status, StatusCode::OK, "{protocol} auth failed: {body}");
    assert_eq!(
        body, r#"{"echo":"/resource?keep=1"}"#,
        "{protocol} forwarded a duplicate API-key query occurrence"
    );
}

struct KeyAuthQueryHarness {
    gateway: TestGateway,
    echo: EchoServer,
    https_port: u16,
}

impl KeyAuthQueryHarness {
    async fn spawn() -> Self {
        let echo = spawn_http_echo().await.expect("spawn echo backend");

        let gateway = TestGateway::builder()
            .mode_file(key_auth_query_config(echo.port))
            .log_level("warn")
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .spawn()
            .await
            .expect("start key-auth query gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");
        let https_port = gateway
            .env_port("FERRUM_PROXY_HTTPS_PORT")
            .expect("harness-allocated HTTPS port");

        Self {
            gateway,
            echo,
            https_port,
        }
    }

    fn http1_url(&self, query: &str) -> String {
        self.gateway.proxy_url(&format!("/resource?{query}"))
    }

    fn h2_uri(&self, query: &str) -> String {
        format!(
            "http://127.0.0.1:{}/resource?{query}",
            self.gateway.proxy_port
        )
    }

    fn h3_url(&self, query: &str) -> String {
        format!("https://localhost:{}/resource?{query}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.echo.abort();
    }
}

fn key_auth_query_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "key-auth-query",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": [{"plugin_config_id": "key-auth-query-plugin"}]
        }],
        "consumers": [{
            "id": "query-consumer",
            "username": "query-user",
            "credentials": {"keyauth": [{"key": "alpha/beta-0123456789"}]}
        }],
        "upstreams": [],
        "plugin_configs": [{
            "id": "key-auth-query-plugin",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "key-auth-query",
            "enabled": true,
            "config": {"key_location": "query:api_key"}
        }]
    });
    serde_yaml::to_string(&config).expect("serialize key-auth query config")
}

async fn http1_request(harness: &KeyAuthQueryHarness, query: &str) -> (StatusCode, String) {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    let response = client
        .get(harness.http1_url(query))
        .send()
        .await
        .expect("http1 key-auth request");
    let status = response.status();
    let body = response.text().await.expect("http1 response body");
    (status, body)
}

async fn h2_request(harness: &KeyAuthQueryHarness, query: &str) -> (StatusCode, String) {
    let stream = TcpStream::connect(("127.0.0.1", harness.gateway.proxy_port))
        .await
        .expect("connect h2c");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = Request::builder()
        .uri(harness.h2_uri(query))
        .body(Empty::<Bytes>::new())
        .expect("build h2 request");
    let response = sender.send_request(request).await.expect("send h2 request");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("collect h2 body")
        .to_bytes();
    drop(sender);
    conn_task.abort();
    (
        status,
        String::from_utf8(body.to_vec()).expect("utf8 h2 body"),
    )
}

async fn h3_request(harness: &KeyAuthQueryHarness, query: &str) -> (StatusCode, String) {
    let client = Http3Client::insecure().expect("h3 client");
    let response =
        h3_request_with_retry(&client, &harness.h3_url(query), GetOptions::default()).await;
    (
        response.status,
        String::from_utf8(response.body_bytes.to_vec()).expect("utf8 h3 body"),
    )
}

async fn h3_request_with_retry(
    client: &Http3Client,
    url: &str,
    options: GetOptions,
) -> crate::scaffolding::clients::Http3Response {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match client.get_with_options(url, options.clone()).await {
            Ok(response) => return response,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 key-auth request did not complete: {error}"),
        }
    }
}
