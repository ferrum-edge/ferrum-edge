//! Functional tests for `Early-Data: 1` admission.
//!
//! `FERRUM_TLS_EARLY_DATA_METHODS` is parsed in config tests, but the live
//! gateway path also needs coverage because H1/H2 requests are rejected before
//! routing when a replay-unsafe method arrives with `Early-Data: 1`.

use crate::common::TestGateway;

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

async fn start_counting_http_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]);
            if !request.contains(" /early ") {
                let _ = stream.shutdown().await;
                return;
            }

            hits.fetch_add(1, Ordering::SeqCst);
            let response = "HTTP/1.1 200 OK\r\n\
                            Content-Length: 2\r\n\
                            Content-Type: text/plain\r\n\
                            Connection: close\r\n\
                            \r\n\
                            ok";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "early-data"
    listen_path: "/early"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: false
    pool_enable_http2: false
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
    )
}

struct EarlyDataHarness {
    gateway: TestGateway,
    hits: Arc<AtomicUsize>,
    backend_task: tokio::task::JoinHandle<()>,
}

impl EarlyDataHarness {
    async fn new(allowed_methods: Option<&str>) -> Self {
        let backend_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let backend_port = backend_listener.local_addr().expect("backend addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let backend_task = tokio::spawn(start_counting_http_backend(
            backend_listener,
            Arc::clone(&hits),
        ));
        sleep(Duration::from_millis(100)).await;

        let mut builder = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("warn");
        if let Some(methods) = allowed_methods {
            builder = builder.env("FERRUM_TLS_EARLY_DATA_METHODS", methods);
        }
        let gateway = builder.spawn().await.expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self {
            gateway,
            hits,
            backend_task,
        }
    }

    fn url(&self) -> String {
        self.gateway.proxy_url("/early")
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for EarlyDataHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

#[ignore]
#[tokio::test]
async fn functional_early_data_h1_enforces_configured_methods() {
    let h = EarlyDataHarness::new(Some("GET")).await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");

    let allowed = client
        .get(h.url())
        .header("Early-Data", "1")
        .send()
        .await
        .expect("early-data GET");
    assert_eq!(allowed.status(), reqwest::StatusCode::OK);
    assert_eq!(allowed.text().await.expect("allowed body"), "ok");
    assert_eq!(h.hits(), 1, "allowed early-data GET should reach backend");

    let rejected = client
        .post(h.url())
        .header("Early-Data", "1")
        .send()
        .await
        .expect("early-data POST");
    assert_eq!(rejected.status(), reqwest::StatusCode::TOO_EARLY);
    let body = rejected.text().await.expect("rejected body");
    assert!(
        body.contains("Method not allowed in 0-RTT early data"),
        "unexpected 425 body: {body}"
    );
    assert_eq!(
        h.hits(),
        1,
        "rejected early-data POST must not reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_early_data_h2_enforces_configured_methods() {
    let h = EarlyDataHarness::new(Some("GET")).await;
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");

    let rejected = client
        .post(h.url())
        .header("Early-Data", "1")
        .send()
        .await
        .expect("early-data H2 POST");
    assert_eq!(rejected.version(), reqwest::Version::HTTP_2);
    assert_eq!(rejected.status(), reqwest::StatusCode::TOO_EARLY);
    let body = rejected.text().await.expect("rejected body");
    assert!(
        body.contains("Method not allowed in 0-RTT early data"),
        "unexpected H2 425 body: {body}"
    );
    assert_eq!(
        h.hits(),
        0,
        "rejected H2 early-data POST must not reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_early_data_header_is_ignored_when_env_not_configured() {
    let h = EarlyDataHarness::new(None).await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client");

    let response = client
        .post(h.url())
        .header("Early-Data", "1")
        .send()
        .await
        .expect("POST with Early-Data and no env gate");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "ok");
    assert_eq!(
        h.hits(),
        1,
        "without FERRUM_TLS_EARLY_DATA_METHODS, Early-Data alone must not reject"
    );
}
