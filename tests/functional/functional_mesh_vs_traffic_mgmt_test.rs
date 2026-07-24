//! Functional coverage for VirtualService traffic-management actions realized
//! through the `mesh_route_dispatch` and `request_mirror` plugins on the live
//! gateway hot path (Tier 3).
//!
//! These spawn the real `ferrum-edge` binary in file mode with a proxy that
//! carries a `mesh_route_dispatch` plugin and assert the BACKEND observes the
//! effect:
//!   - `rewrite.uri` rewrites the request path forwarded to the backend
//!     (prefix-rewrite semantics).
//!   - `rewrite.authority` rewrites the forwarded `Host` header.
//!   - `redirect` short-circuits before the backend with a 3xx + `Location`.
//!   - `mirror` (request_mirror plugin) replays the request to a second
//!     backend without blocking the primary response.
//!
//! Run with:
//!   cargo test --test functional_tests functional_mesh_vs_traffic_mgmt -- --ignored --nocapture

use crate::common::TestGateway;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// A backend that records the request line (`METHOD PATH`) and `Host` header
/// of every request it receives, then answers `200 OK`.
struct RecordingBackend {
    port: u16,
    request_lines: Arc<Mutex<Vec<String>>>,
    host_headers: Arc<Mutex<Vec<String>>>,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl RecordingBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind backend");
        let port = listener.local_addr().expect("backend addr").port();
        let request_lines = Arc::new(Mutex::new(Vec::new()));
        let host_headers = Arc::new(Mutex::new(Vec::new()));
        let hits = Arc::new(AtomicUsize::new(0));

        let request_lines_task = Arc::clone(&request_lines);
        let host_headers_task = Arc::clone(&host_headers);
        let hits_task = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let request_lines = Arc::clone(&request_lines_task);
                let host_headers = Arc::clone(&host_headers_task);
                let hits = Arc::clone(&hits_task);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n =
                        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                            .await
                        {
                            Ok(Ok(n)) if n > 0 => n,
                            _ => return,
                        };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    if let Some(line) = request.lines().next() {
                        request_lines.lock().await.push(line.to_string());
                    }
                    for line in request.lines() {
                        if let Some(host) = line
                            .strip_prefix("Host: ")
                            .or_else(|| line.strip_prefix("host: "))
                        {
                            host_headers.lock().await.push(host.trim().to_string());
                        }
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
        });
        sleep(Duration::from_millis(100)).await;
        Self {
            port,
            request_lines,
            host_headers,
            hits,
            task,
        }
    }

    async fn request_lines(&self) -> Vec<String> {
        self.request_lines.lock().await.clone()
    }

    async fn host_headers(&self) -> Vec<String> {
        self.host_headers.lock().await.clone()
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for RecordingBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn h1_client() -> reqwest::Client {
    reqwest::Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("h1 client")
}

#[ignore]
#[tokio::test]
async fn functional_mesh_vs_traffic_mgmt_rewrite_uri_rewrites_backend_path() {
    let backend = RecordingBackend::start().await;
    // Proxy on `/api` with a mesh_route_dispatch rewrite: prefix `/api` →
    // `/internal`. A request to `/api/users/42` must reach the backend as
    // `/internal/users/42`.
    let config = format!(
        r#"version: "1"
proxies:
  - id: "rewrite-proxy"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "mrd-rewrite"
consumers: []
plugin_configs:
  - id: "mrd-rewrite"
    plugin_name: "mesh_route_dispatch"
    scope: "proxy"
    proxy_id: "rewrite-proxy"
    enabled: true
    config:
      rules:
        - match:
            methods: ["GET"]
          destination:
            backend_host: "127.0.0.1"
            backend_port: {port}
          rewrite:
            uri: "/internal"
            match_prefix: "/api"
"#,
        port = backend.port
    );
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = h1_client();
    let resp = client
        .get(gateway.proxy_url("/api/users/42"))
        .send()
        .await
        .expect("send request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let lines = backend.request_lines().await;
    assert!(
        lines.iter().any(|l| l == "GET /internal/users/42 HTTP/1.1"),
        "backend must observe the rewritten path, got: {lines:?}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_vs_traffic_mgmt_rewrite_authority_rewrites_host() {
    let backend = RecordingBackend::start().await;
    let config = format!(
        r#"version: "1"
proxies:
  - id: "rewrite-authority"
    listen_path: "/svc"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "mrd-authority"
consumers: []
plugin_configs:
  - id: "mrd-authority"
    plugin_name: "mesh_route_dispatch"
    scope: "proxy"
    proxy_id: "rewrite-authority"
    enabled: true
    config:
      rules:
        - match:
            methods: ["GET"]
          destination:
            backend_host: "127.0.0.1"
            backend_port: {port}
          rewrite:
            authority: "internal.example.com"
"#,
        port = backend.port
    );
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = h1_client();
    let resp = client
        .get(gateway.proxy_url("/svc/thing"))
        .send()
        .await
        .expect("send request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let hosts = backend.host_headers().await;
    assert!(
        hosts.iter().any(|h| h == "internal.example.com"),
        "backend must observe the rewritten Host, got: {hosts:?}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_vs_traffic_mgmt_redirect_short_circuits_backend() {
    let backend = RecordingBackend::start().await;
    let config = format!(
        r#"version: "1"
proxies:
  - id: "redirect-proxy"
    listen_path: "/old"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "mrd-redirect"
consumers: []
plugin_configs:
  - id: "mrd-redirect"
    plugin_name: "mesh_route_dispatch"
    scope: "proxy"
    proxy_id: "redirect-proxy"
    enabled: true
    config:
      rules:
        - match: {{}}
          redirect:
            uri: "/new"
            authority: "elsewhere.example.com"
            scheme: "https"
            redirect_code: 308
"#,
        port = backend.port
    );
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = h1_client();
    let resp = client
        .get(gateway.proxy_url("/old/page"))
        .send()
        .await
        .expect("send request");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::PERMANENT_REDIRECT,
        "redirect rule must return its 3xx"
    );
    assert_eq!(
        resp.headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("https://elsewhere.example.com/new")
    );
    // The redirected request must never reach the backend — the redirect
    // short-circuits dispatch in before_proxy. (The gateway may probe the
    // configured backend once at startup for HTTP/2 capability, so assert on
    // the request path rather than a zero hit count.)
    sleep(Duration::from_millis(200)).await;
    let lines = backend.request_lines().await;
    assert!(
        !lines.iter().any(|l| l.contains("/old/page")),
        "redirect must short-circuit before the backend; backend saw: {lines:?}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_mesh_vs_traffic_mgmt_mirror_replays_to_second_backend() {
    let primary = RecordingBackend::start().await;
    let mirror = RecordingBackend::start().await;
    // The route rewrites URI + authority before primary dispatch; the
    // request_mirror plugin must replay that same selected route to `mirror`
    // with Envoy's shadow-host suffix.
    let config = format!(
        r#"version: "1"
proxies:
  - id: "mirror-proxy"
    listen_path: "/shadow"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {primary_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "mrd-mirror"
      - plugin_config_id: "mirror-plugin"
consumers: []
plugin_configs:
  - id: "mrd-mirror"
    plugin_name: "mesh_route_dispatch"
    scope: "proxy"
    proxy_id: "mirror-proxy"
    enabled: true
    config:
      rules:
        - match:
            methods: ["GET"]
          destination:
            backend_host: "127.0.0.1"
            backend_port: {primary_port}
          rewrite:
            uri: "/internal"
            match_prefix: "/shadow"
            authority: "internal.example.com"
  - id: "mirror-plugin"
    plugin_name: "request_mirror"
    scope: "proxy"
    proxy_id: "mirror-proxy"
    enabled: true
    config:
      mirror_host: "127.0.0.1"
      mirror_port: {mirror_port}
      percentage: 100.0
"#,
        primary_port = primary.port,
        mirror_port = mirror.port,
    );
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = h1_client();
    let resp = client
        .get(gateway.proxy_url("/shadow/ping"))
        .send()
        .await
        .expect("send request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert!(primary.hits() >= 1, "primary backend must be hit");
    let primary_lines = primary.request_lines().await;
    assert!(
        primary_lines
            .iter()
            .any(|line| line == "GET /internal/ping HTTP/1.1"),
        "primary backend must observe the matched route rewrite: {primary_lines:?}"
    );
    let primary_hosts = primary.host_headers().await;
    assert!(
        primary_hosts
            .iter()
            .any(|host| host == "internal.example.com"),
        "primary backend must observe the rewritten authority without a shadow suffix: {primary_hosts:?}"
    );

    // The mirror is fire-and-forget; poll briefly for the shadowed request.
    let deadline = Instant::now() + Duration::from_secs(3);
    while mirror.hits() == 0 && Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        mirror.hits() >= 1,
        "mirror backend must receive the shadowed request"
    );
    let lines = mirror.request_lines().await;
    assert!(
        lines.iter().any(|l| l == "GET /internal/ping HTTP/1.1"),
        "mirror must replay the matched route rewrite, got: {lines:?}"
    );
    let hosts = mirror.host_headers().await;
    assert!(
        hosts
            .iter()
            .any(|host| host == "internal.example.com-shadow"),
        "mirror must carry the rewritten authority with -shadow, got: {hosts:?}"
    );
}
