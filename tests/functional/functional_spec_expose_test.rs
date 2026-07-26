//! End-to-end `spec_expose` coverage across HTTP/1.1, HTTP/2, and HTTP/3.

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client, Http3Response};

use http::{HeaderMap, Method, StatusCode};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::sleep;

const SPEC_SOURCE_BODY: &str = r#"{"openapi":"3.1.0","info":{"title":"Ferrum"}}"#;

struct StaticServer {
    port: u16,
    hits: Arc<AtomicUsize>,
    h2c_probes: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl StaticServer {
    async fn start(body: &'static str, content_type: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind static server");
        let port = listener.local_addr().expect("static server addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2c_probes = Arc::new(AtomicUsize::new(0));
        let task_hits = Arc::clone(&hits);
        let task_h2c_probes = Arc::clone(&h2c_probes);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let hits = Arc::clone(&task_hits);
                let h2c_probes = Arc::clone(&task_h2c_probes);
                tokio::spawn(async move {
                    let mut reader = BufReader::new(stream);
                    let mut request_line = Vec::with_capacity(128);
                    let Ok(Ok(read)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        reader.read_until(b'\n', &mut request_line),
                    )
                    .await
                    else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    // File-mode startup sends an HTTP/2 prior-knowledge preface
                    // to each plaintext backend to populate the capability
                    // registry even when pool warmup is disabled. Keep that
                    // protocol probe separate from HTTP/1 requests routed by
                    // the gateway so the assertions below measure only real
                    // backend traffic.
                    if request_line.starts_with(b"PRI * HTTP/2.0") {
                        h2c_probes.fetch_add(1, Ordering::SeqCst);
                    } else {
                        hits.fetch_add(1, Ordering::SeqCst);
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let mut stream = reader.into_inner();
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });

        Self {
            port,
            hits,
            h2c_probes,
            task,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn h2c_probes(&self) -> usize {
        self.h2c_probes.load(Ordering::SeqCst)
    }
}

impl Drop for StaticServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn build_config(backend_port: u16, spec_origin_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "spec-trailing-prefix"
    listen_path: "/api/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: [GET, HEAD]
  - id: "spec-head-blocked"
    listen_path: "/blocked/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    pool_enable_http2: false
    allowed_methods: [GET]

consumers: []
plugin_configs:
  - id: "spec-expose-global"
    plugin_name: spec_expose
    scope: global
    enabled: true
    priority_override: 211
    config:
      spec_url: "http://127.0.0.1:{spec_origin_port}/private/openapi.yaml?token=signed"
      cache_ttl_seconds: 60
  - id: "spec-response-transform"
    plugin_name: response_transformer
    scope: global
    enabled: true
    config:
      rules:
        - operation: add
          target: body
          key: head_parity
          value: checked
"#
    )
}

fn assert_spec_metadata(headers: &HeaderMap) -> usize {
    assert_eq!(
        headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let content_length = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .expect("spec response Content-Length");
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    content_length
}

fn assert_transformed_spec(body: &str) {
    let document: serde_json::Value = serde_json::from_str(body).expect("transformed JSON spec");
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(document["info"]["title"], "Ferrum");
    assert_eq!(document["head_parity"], "checked");
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

async fn spawn_spec_gateway(backend_port: u16, spec_origin_port: u16) -> (TestGateway, u16) {
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
            .mode_file(build_config(backend_port, spec_origin_port))
            .log_level("warn")
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
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    panic!("failed to spawn spec_expose H3 gateway after {MAX_ATTEMPTS} attempts: {last_error}");
}

#[ignore]
#[tokio::test]
async fn functional_spec_expose_get_head_path_and_method_contract_across_http_versions() {
    let origin = StaticServer::start(SPEC_SOURCE_BODY, "application/json").await;
    let backend = StaticServer::start("ordinary backend", "text/plain").await;

    let (mut gateway, https_port) = spawn_spec_gateway(backend.port, origin.port).await;
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    // The binary harness disables pool warmup, so file-mode startup performs
    // asynchronous h2c capability discovery against the shared backend. A
    // refresh/pool lifecycle can open more than one prior-knowledge connection;
    // wait until those prefaces have settled, then preserve that count as the
    // startup baseline. The routing contract below is that spec requests add
    // neither an HTTP/1 backend hit nor another h2c connection.
    let probe_deadline = Instant::now() + Duration::from_secs(5);
    let probe_quiet_period = Duration::from_millis(500);
    let mut startup_h2c_probes = backend.h2c_probes();
    let mut probes_stable_since = Instant::now();
    while startup_h2c_probes == 0 || probes_stable_since.elapsed() < probe_quiet_period {
        assert!(
            Instant::now() < probe_deadline,
            "startup h2c probes did not settle (observed {startup_h2c_probes})"
        );
        sleep(Duration::from_millis(10)).await;
        let observed = backend.h2c_probes();
        if observed != startup_h2c_probes {
            startup_h2c_probes = observed;
            probes_stable_since = Instant::now();
        }
    }
    assert!(startup_h2c_probes > 0);
    assert_eq!(backend.hits(), 0);

    let h1 = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("H1 client");
    let canonical = gateway.proxy_url("/api/specz?download=true");

    // HEAD on a cold cache performs the same origin GET as the representation,
    // but returns metadata only.
    let h1_head = h1.head(&canonical).send().await.expect("H1 HEAD");
    assert_eq!(h1_head.status(), reqwest::StatusCode::OK);
    let representation_length = assert_spec_metadata(h1_head.headers());
    assert!(representation_length > SPEC_SOURCE_BODY.len());
    assert!(h1_head.bytes().await.expect("H1 HEAD body").is_empty());
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 0);
    assert_eq!(backend.h2c_probes(), startup_h2c_probes);

    let h1_get = h1.get(&canonical).send().await.expect("H1 GET");
    assert_eq!(h1_get.status(), reqwest::StatusCode::OK);
    assert_eq!(
        assert_spec_metadata(h1_get.headers()),
        representation_length
    );
    let h1_body = h1_get.text().await.expect("H1 GET body");
    assert_eq!(h1_body.len(), representation_length);
    assert_transformed_spec(&h1_body);
    assert_eq!(
        origin.hits(),
        1,
        "GET should reuse the HEAD-populated cache"
    );

    // The double-slash alias is deliberately ordinary backend traffic.
    let alias = h1
        .get(gateway.proxy_url("/api//specz"))
        .send()
        .await
        .expect("H1 double-slash alias");
    assert_eq!(alias.text().await.expect("alias body"), "ordinary backend");
    assert_eq!(backend.hits(), 1);

    // Encoded separators do not become the plugin-owned resource. Since the
    // canonical-policy-path fix (advisory GHSA-69xf-42xm-4w4f) they are
    // refused at the frontend boundary rather than folded into `/`, so the
    // request reaches neither the plugin nor a backend.
    let encoded = h1
        .get(gateway.proxy_url("/api%2Fspecz"))
        .send()
        .await
        .expect("H1 encoded separator");
    assert_eq!(encoded.status(), reqwest::StatusCode::BAD_REQUEST);
    let encoded_body = encoded.text().await.expect("encoded body");
    assert!(!encoded_body.contains("\"openapi\""));
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 1);

    // Route method admission runs before the plugin and can exclude HEAD.
    let blocked = h1
        .head(gateway.proxy_url("/blocked/specz"))
        .send()
        .await
        .expect("H1 blocked HEAD");
    assert_eq!(blocked.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 1);

    let h2 = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h2c client");
    let h2_get = h2.get(&canonical).send().await.expect("H2 GET");
    assert_eq!(h2_get.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        assert_spec_metadata(h2_get.headers()),
        representation_length
    );
    let h2_body = h2_get.text().await.expect("H2 GET body");
    assert_eq!(h2_body.len(), representation_length);
    assert_transformed_spec(&h2_body);
    let h2_head = h2.head(&canonical).send().await.expect("H2 HEAD");
    assert_eq!(h2_head.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        assert_spec_metadata(h2_head.headers()),
        representation_length
    );
    assert!(h2_head.bytes().await.expect("H2 HEAD body").is_empty());

    let h3 = Http3Client::insecure().expect("H3 client");
    let h3_url = format!("https://localhost:{https_port}/api/specz?download=true");
    let h3_get = h3_request_until_ready(&h3, &h3_url, Method::GET).await;
    assert_eq!(h3_get.status, StatusCode::OK);
    assert_eq!(assert_spec_metadata(&h3_get.headers), representation_length);
    assert_eq!(h3_get.body_bytes.len(), representation_length);
    assert_transformed_spec(&h3_get.body_text());
    let h3_head = h3_request_until_ready(&h3, &h3_url, Method::HEAD).await;
    assert_eq!(h3_head.status, StatusCode::OK);
    assert_eq!(
        assert_spec_metadata(&h3_head.headers),
        representation_length
    );
    assert!(h3_head.body_bytes.is_empty());

    let h3_blocked_url = format!("https://localhost:{https_port}/blocked/specz");
    let h3_blocked = h3_request_until_ready(&h3, &h3_blocked_url, Method::HEAD).await;
    assert_eq!(h3_blocked.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(origin.hits(), 1);
    assert_eq!(backend.hits(), 1);
    assert_eq!(backend.h2c_probes(), startup_h2c_probes);

    gateway.shutdown();
}
