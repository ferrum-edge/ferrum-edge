//! Functional coverage for query-parameter count limits across frontend protocols.
//!
//! These tests exercise `FERRUM_MAX_QUERY_PARAMS` on HTTP/1.1, h2c, and HTTP/3
//! and lock H3 to the same empty-segment semantics as the H1/H2 proxy path.

use crate::common::{EchoServer, TestGateway, spawn_http_echo};
use crate::scaffolding::clients::Http3Client;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

const MAX_QUERY_PARAMS: &str = "2";
const EMPTY_SEGMENT_QUERY: &str = "a=1&&b=2&";
const EMPTY_KEY_WITHIN_LIMIT_QUERY: &str = "a=1&=empty";
const EMPTY_KEY_OVER_LIMIT_QUERY: &str = "a=1&=empty&b=2";
const TOO_MANY_QUERY_PARAMS: &str = "a=1&b=2&c=3";

#[ignore]
#[tokio::test]
async fn functional_query_param_limit_skips_empty_segments_h1_h2_h3() {
    let mut harness = QueryLimitHarness::spawn().await;

    assert_http1_status(&harness, EMPTY_SEGMENT_QUERY, StatusCode::OK).await;
    assert_h2_status(&harness, EMPTY_SEGMENT_QUERY, StatusCode::OK).await;
    assert_h3_status(&harness, EMPTY_SEGMENT_QUERY, StatusCode::OK).await;

    assert_http1_status(&harness, EMPTY_KEY_WITHIN_LIMIT_QUERY, StatusCode::OK).await;
    assert_h2_status(&harness, EMPTY_KEY_WITHIN_LIMIT_QUERY, StatusCode::OK).await;
    assert_h3_status(&harness, EMPTY_KEY_WITHIN_LIMIT_QUERY, StatusCode::OK).await;

    harness.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_query_param_limit_rejects_excess_params_h1_h2_h3() {
    let mut harness = QueryLimitHarness::spawn().await;

    assert_http1_status(&harness, TOO_MANY_QUERY_PARAMS, StatusCode::BAD_REQUEST).await;
    assert_h2_status(&harness, TOO_MANY_QUERY_PARAMS, StatusCode::BAD_REQUEST).await;
    assert_h3_status(&harness, TOO_MANY_QUERY_PARAMS, StatusCode::BAD_REQUEST).await;

    assert_http1_status(
        &harness,
        EMPTY_KEY_OVER_LIMIT_QUERY,
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_h2_status(
        &harness,
        EMPTY_KEY_OVER_LIMIT_QUERY,
        StatusCode::BAD_REQUEST,
    )
    .await;
    assert_h3_status(
        &harness,
        EMPTY_KEY_OVER_LIMIT_QUERY,
        StatusCode::BAD_REQUEST,
    )
    .await;

    harness.shutdown();
}

struct QueryLimitHarness {
    gateway: TestGateway,
    echo: EchoServer,
    https_port: u16,
}

impl QueryLimitHarness {
    async fn spawn() -> Self {
        let echo = spawn_http_echo().await.expect("spawn echo backend");
        let https_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve https port");
        let https_port = https_listener.local_addr().expect("https addr").port();
        drop(https_listener);

        let gateway = TestGateway::builder()
            .mode_file(query_limit_config(echo.port))
            .log_level("warn")
            .env("FERRUM_MAX_QUERY_PARAMS", MAX_QUERY_PARAMS)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
            .spawn()
            .await
            .expect("start query-limit gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(5))
            .await
            .expect("proxy port ready");

        Self {
            gateway,
            echo,
            https_port,
        }
    }

    fn http1_url(&self, query: &str) -> String {
        self.gateway.proxy_url(&format!("/search?{query}"))
    }

    fn h2_uri(&self, query: &str) -> String {
        format!(
            "http://127.0.0.1:{}/search?{query}",
            self.gateway.proxy_port
        )
    }

    fn h3_url(&self, query: &str) -> String {
        format!("https://localhost:{}/search?{query}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.echo.abort();
    }
}

fn query_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "query-limits",
            "listen_path": "/",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize query-limit config")
}

async fn assert_http1_status(harness: &QueryLimitHarness, query: &str, expected: StatusCode) {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");
    let resp = client
        .get(harness.http1_url(query))
        .send()
        .await
        .expect("http1 query-limit request");

    assert_eq!(resp.status(), expected, "query={query}");
}

async fn assert_h2_status(harness: &QueryLimitHarness, query: &str, expected: StatusCode) {
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

    let req = Request::builder()
        .uri(harness.h2_uri(query))
        .body(Empty::<Bytes>::new())
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("send h2 request");

    assert_eq!(resp.status(), expected, "query={query}");
    let _ = resp.into_body().collect().await;

    drop(sender);
    conn_task.abort();
}

async fn assert_h3_status(harness: &QueryLimitHarness, query: &str, expected: StatusCode) {
    let client = Http3Client::insecure().expect("h3 client");
    let url = harness.h3_url(query);
    let mut last_err = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let resp = loop {
        match client.get(&url).await {
            Ok(resp) => break resp,
            Err(err) if std::time::Instant::now() < deadline => {
                last_err = Some(err.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 query-limit request did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    };

    assert_eq!(resp.status, expected, "query={query}");
}
